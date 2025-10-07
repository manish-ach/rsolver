use std::{collections::HashMap, error::Error, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::RwLock, time::Instant};

struct CachedEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

impl Clone for CachedEntry {
    fn clone(&self) -> Self {
        CachedEntry {
            response: self.response.clone(),
            expires_at: self.expires_at,
        }
    }
}

type Cache = Arc<RwLock<HashMap<String, CachedEntry>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:8001").await?;
    println!("server listening on 127.0.0.1:8001");
    let mut buf = [0u8; 512];

    let upstream_addr = "8.8.8.8:53";
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;

    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        println!("Recieved data addr is {client_addr} and the len is {len}");

        let query = buf[..len].to_vec();

        let cache_key = match get_query_key(&query) {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Failed to get cache key");
                continue;
            }
        };

        if let Some(mut entry) = get_cached_response(&cache, &cache_key).await {
            println!("Cache hit for {cache_key}");

            let client_id = u16::from_be_bytes([query[0], query[1]]);
            fix_response_id(&mut entry.response, client_id);
            socket.send_to(&entry.response, client_addr).await?;
            continue;
        }

        println!("Cache miss for {cache_key}, forwarding upstream");

        upstream.send_to(&query, upstream_addr).await?;
        println!("query forwarded upstream to {upstream_addr}");

        // RESPONSE
        let mut response = [0u8; 512];
        let (response_len, _) = upstream.recv_from(&mut response).await?;
        let response_data = response[..response_len].to_vec();

        if let Err(e) = parse_dns_query(&response_data) {
            eprintln!("failed to parse the packet: {e}");
        }

        let ttl = extract_min_ttl(&response_data).unwrap_or(60);
        cache_response(&cache, cache_key.clone(), response_data.clone(), ttl).await;
        println!("Cached response for {cache_key} with TTL={ttl}s");

        socket
            .send_to(&response[..response_len], client_addr)
            .await?;
        println!("Sent response to {client_addr}\n");
    }
}

// <!-----CACHE HELPERS-----!>
async fn get_cached_response(cache: &Cache, key: &str) -> Option<CachedEntry> {
    let map = cache.read().await;
    map.get(key).and_then(|entry| {
        if entry.expires_at > Instant::now() {
            Some(entry.clone())
        } else {
            None
        }
    })
}

fn fix_response_id(response: &mut [u8], client_id: u16) {
    if response.len() >= 2 {
        response[0..2].copy_from_slice(&client_id.to_be_bytes());
    }
}

async fn cache_response(cache: &Cache, key: String, response: Vec<u8>, ttl: u32) {
    let mut map = cache.write().await;
    map.insert(
        key,
        CachedEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
        },
    );
}

// <!------QUERY HELPER ------!>
fn get_query_key(data: &[u8]) -> Result<String, Box<dyn Error>> {
    let (qname, offset) = read_qname(data, 12)?;
    if offset + 2 > data.len() {
        return Err("Invalid Query Length".into());
    }

    let qytpe = u16::from_be_bytes([data[offset], data[offset + 1]]);
    Ok(format!("{}|{}", qytpe, qname))
}

fn extract_min_ttl(data: &[u8]) -> Option<u32> {
    if data.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut offset = 12;

    for _ in 0..qdcount {
        let (_, new_offset) = read_qname(data, offset).ok()?;
        offset = new_offset + 4 //skip type and class
    }

    for _ in 0..ancount {
        let (_, new_offset) = read_qname(data, offset).ok()?;
        offset = new_offset;
        if offset + 10 > data.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        return Some(ttl);
    }
    None
}

// <!------DNS PARSERS-------!>
fn parse_dns_query(data: &[u8]) -> Result<(), Box<dyn Error>> {
    if data.len() < 12 {
        return Err("Packet too short".into());
    }

    // <!-----HEADER------!>
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    println!("-----DNS HEADER-----");
    println!("ID: {}", id);
    println!("Flags: 0x{:04x}", flags);
    println!("Questions: {}", qdcount);
    println!(
        "Answers: {}, Security: {}, Additional: {}",
        ancount, nscount, arcount
    );

    // <!-----QUESTION------!>
    let mut offset = 12;

    for _ in 0..qdcount {
        let (qname, new_offset) = read_qname(data, offset)?;
        offset = new_offset;

        if offset + 4 > data.len() {
            return Err("Incomplete Question".into());
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

        println!("--- QUESTION ---");
        println!("Name: {}", qname);
        println!("Type: {} ({:?})", qtype, record_type_name(qtype));
        println!("Class: {}", qclass);
        offset += 4;
    }

    // <!-----ANSWER------!>
    for _ in 0..ancount {
        let (name, new_offset) = read_qname(data, offset)?;
        offset = new_offset;

        if (offset + 10) > data.len() {
            return Err("Incomplete answer record".into());
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        let rdata = &data[offset..offset + rdlength];
        offset += rdlength;

        println!(
            "Answer: {name}  TTL={ttl}  TYPE={rtype} ({})",
            record_type_name(rtype)
        );

        // If it's an A record (IPv4)
        if rtype == 1 && rdlength == 4 {
            println!(
                "→ IPv4 Address: {}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            );
        }
    }

    Ok(())
}

fn read_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0usize;

    loop {
        if offset >= data.len() {
            return Err("QNAME extends beyond packet".into());
        }

        let len = data[offset];

        // compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return Err("Incomplete compression pointer".into());
            }
            let pointer = (((len & 0x3F) as u16) << 8) | data[offset + 1] as u16;

            if !jumped {
                jump_offset = offset + 2;
                jumped = true;
            }

            offset = pointer as usize;
            continue;
        } else if len == 0 {
            offset += 1;
            break;
        }

        offset += 1;
        if offset + (len as usize) > data.len() {
            return Err("label extends beyond the packet".into());
        }

        let label = String::from_utf8(data[offset..offset + (len as usize)].to_vec())?;
        labels.push(label);
        offset += len as usize;
    }
    let name = labels.join(".");
    Ok((name, if jumped { jump_offset } else { offset }))
}

fn record_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        28 => "AAAA",
        _ => "UNKNOWN",
    }
}
