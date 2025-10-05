use std::error::Error;

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:8001").await?;
    println!("server listening on 127.0.0.1:8001");
    let mut buf = [0u8; 512];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("Recieved data addr is {addr} and the len is {len}");

        if let Err(e) = parse_dns_query(&buf[..len]) {
            eprintln!("failed to parse the packet: {e}");
        }
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

    Ok(())
}

fn read_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels = Vec::new();

    loop {
        if offset >= data.len() {
            return Err("QNAME extends beyond packet".into());
        }

        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }

        offset += 1;
        if offset + len > data.len() {
            return Err("label extends beyond the packet".into());
        }

        let label = String::from_utf8(data[offset..offset + len].to_vec())?;
        labels.push(label);
        offset += len;
    }
    let name = labels.join(".");
    Ok((name, offset))
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
