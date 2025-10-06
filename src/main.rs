use std::error::Error;

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:8001").await?;
    println!("server listening on 127.0.0.1:8001");
    let mut buf = [0u8; 512];

    let upstream_addr = "8.8.8.8:53";
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        println!("Recieved data addr is {client_addr} and the len is {len}");

        if let Err(e) = parse_dns_query(&buf[..len]) {
            eprintln!("failed to parse the packet: {e}");
        }

        upstream.send_to(&buf[..len], upstream_addr).await?;
        println!("query forwarded upstream to {upstream_addr}");

        // RESPONSE
        let mut response = [0u8; 512];
        let (response_len, _) = upstream.recv_from(&mut response).await?;

        if let Err(e) = parse_dns_query(&response[..response_len]) {
            eprintln!("failed to parse the packet: {e}");
        }

        socket
            .send_to(&response[..response_len], client_addr)
            .await?;
        println!("Sent response to {client_addr}\n");
    }
}

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
