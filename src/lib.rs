use anyhow::{anyhow, Context, Result};
use byteorder::{ReadBytesExt, WriteBytesExt};
use rand::Rng;
use std::{
    io::{Cursor, Read, Seek, Write},
    net::{IpAddr, Ipv4Addr},
};

#[derive(Debug)]
struct DNSQuery {
    header: DNSHeader,
    question: DNSQuestion,
}

#[derive(Debug, PartialEq)]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
    pub name: Vec<u8>,
    pub r#type: RecordType,
    pub class: RecordClass,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RecordType {
    ///  1 a host address
    A,
    /// 2 an authoritative name server
    NS,
    /// 3 a mail destination (Obsolete - use MX)
    MD,
    /// 4 a mail forwarder (Obsolete - use MX)
    MF,
    /// 5 the canonical name for an alias
    CNAME,
    /// 6 marks the start of a zone of authority
    SOA,
    /// 7 a mailbox domain name (EXPERIMENTAL)
    MB,
    /// 8 a mail group member (EXPERIMENTAL)
    MG,
    /// 9 a mail rename domain name (EXPERIMENTAL)
    MR,
    /// 10 a null RR (EXPERIMENTAL)
    NULL,
    /// 11 a well known service description
    WKS,
    /// 12 a domain name pointer
    PTR,
    /// 13 host information
    HINFO,
    /// 14 mailbox or mail list information
    MINFO,
    /// 15 mail exchange
    MX,
    /// 16 text strings
    TXT,
    // 28 IPv6 address record
    AAAA,
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            value => unreachable!("value={value}"),
        }
    }
}

impl RecordType {
    fn as_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RecordClass {
    In,
}

impl From<u16> for RecordClass {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordClass::In,
            value => unreachable!("value={value}"),
        }
    }
}

impl RecordClass {
    fn as_u16(&self) -> u16 {
        match self {
            RecordClass::In => 1,
        }
    }
}

#[derive(Debug)]
pub struct DNSRecord {
    pub name: Vec<u8>,
    pub r#type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

fn header_to_bytes(header: &DNSHeader, mut writer: impl std::io::Write) -> std::io::Result<()> {
    writer.write_u16::<byteorder::BigEndian>(header.id)?;
    writer.write_u16::<byteorder::BigEndian>(header.flags)?;
    writer.write_u16::<byteorder::BigEndian>(header.num_questions)?;
    writer.write_u16::<byteorder::BigEndian>(header.num_answers)?;
    writer.write_u16::<byteorder::BigEndian>(header.num_authorities)?;
    writer.write_u16::<byteorder::BigEndian>(header.num_additionals)?;
    Ok(())
}

fn question_to_bytes(
    question: &DNSQuestion,
    mut writer: impl std::io::Write,
) -> std::io::Result<()> {
    writer.write_all(&question.name)?;
    writer.write_u16::<byteorder::BigEndian>(question.r#type.as_u16())?;
    writer.write_u16::<byteorder::BigEndian>(question.class.as_u16())?;
    Ok(())
}

fn dns_query_to_bytes(query: &DNSQuery) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();

    let mut cursor = Cursor::new(&mut buffer);

    header_to_bytes(&query.header, &mut cursor)?;

    question_to_bytes(&query.question, &mut cursor)?;

    Ok(buffer)
}

#[cfg(test)]
#[test]
fn test_dns_query_to_bytes() -> std::io::Result<()> {
    let query = DNSQuery {
        header: DNSHeader {
            id: 3,
            flags: 0,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        },
        question: DNSQuestion {
            name: encode_dns_name("example.com")?,
            r#type: RecordType::A,
            class: RecordClass::In,
        },
    };

    let expected =
        b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            .to_vec();

    let bytes = dns_query_to_bytes(&query)?;

    assert_eq!(expected, bytes);

    Ok(())
}

fn encode_dns_name(domain_name: &str) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();

    for piece in domain_name.split('.') {
        buffer.write_u8(piece.len() as u8)?;
        buffer.write_all(piece.as_bytes())?;
    }

    buffer.write_u8(0)?;

    Ok(buffer)
}

#[cfg(test)]
#[test]
fn test_encode_dns_name() {
    let tests = [
        ("", vec![0, 0]),
        ("google", b"\x06google\x00".to_vec()),
        ("google.com", b"\x06google\x03com\x00".to_vec()),
        (
            "image.google.com",
            b"\x05image\x06google\x03com\x00".to_vec(),
        ),
    ];

    for (input, expected) in tests {
        let actual = encode_dns_name(input).unwrap();
        assert_eq!(expected, actual);
    }
}

fn is_compressed(length: u8) -> bool {
    length & 0b1100_0000 == 0b1100_0000
}

fn decode_compressed_name(length: u8, reader: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    // Discard first two bits of the length and add the next byte
    // to get the position of the domain name.
    let pointer_bytes = [length & 0b0011_1111, reader.read_u8()?];
    let pointer = Cursor::new(pointer_bytes).read_u16::<byteorder::BigEndian>()?;

    let original_position = reader.position();

    reader.seek(std::io::SeekFrom::Start(pointer as u64))?;

    let decoded_dns_name = decode_dns_name(reader)?;

    reader.seek(std::io::SeekFrom::Start(original_position))?;

    Ok(decoded_dns_name)
}

fn decode_dns_name(reader: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let mut name = Vec::new();

    loop {
        let length = reader.read_u8()?;
        // Reached the end of the domain name.
        if length == 0 {
            break;
        }

        let compressed = is_compressed(length);

        let mut part = if compressed {
            decode_compressed_name(length, reader).context("decoding compressed domain name")?
        } else {
            let mut buffer = vec![0_u8; length as usize];

            reader
                .read_exact(&mut buffer)
                .context("reading data into domain name buffer")?;
            buffer
        };

        // Given the domain: google.com
        // If this part is the `google` in google.com
        if name.is_empty() {
            name.append(&mut part);
        } else {
            // If this part is the `com` in google.com
            // add a . before appending it.
            name.push(b'.');
            name.append(&mut part);
        }

        if compressed {
            break;
        }
    }

    Ok(name)
}

#[cfg(test)]
#[test]
fn test_decode_dns_name() -> Result<()> {
    let decoded_dns_name =
        decode_dns_name(&mut Cursor::new(b"\x03www\x07example\x03com\x00\x00\x01"))?;

    let decoded_dns_name_string = String::from_utf8(decoded_dns_name).unwrap();

    assert_eq!("www.example.com", decoded_dns_name_string);

    Ok(())
}

fn build_query(id: u16, domain_name: &str, record_type: RecordType) -> std::io::Result<Vec<u8>> {
    let header = DNSHeader {
        id,
        flags: 0,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };

    let question: DNSQuestion = DNSQuestion {
        name: encode_dns_name(domain_name)?,
        r#type: record_type,
        class: RecordClass::In,
    };

    let dns_query = DNSQuery { header, question };

    dns_query_to_bytes(&dns_query)
}

#[cfg(test)]
#[test]
fn test_build_query() -> std::io::Result<()> {
    let query_id = 2;

    let query = build_query(query_id, "example.com", RecordType::A)?;

    let expected =
        b"\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            .to_vec();

    assert_eq!(expected, query);

    Ok(())
}

fn parse_dns_header(reader: &mut Cursor<&[u8]>) -> std::io::Result<DNSHeader> {
    let id = reader.read_u16::<byteorder::BigEndian>()?;
    let flags = reader.read_u16::<byteorder::BigEndian>()?;
    let num_questions = reader.read_u16::<byteorder::BigEndian>()?;
    let num_answers = reader.read_u16::<byteorder::BigEndian>()?;
    let num_authorities = reader.read_u16::<byteorder::BigEndian>()?;
    let num_additionals = reader.read_u16::<byteorder::BigEndian>()?;

    Ok(DNSHeader {
        id,
        flags,
        num_questions,
        num_answers,
        num_authorities,
        num_additionals,
    })
}

#[cfg(test)]
#[test]
fn test_parse_dns_header() -> std::io::Result<()> {
    let original_header = DNSHeader {
        id: 31,
        flags: 0,
        num_questions: 1,
        num_answers: 1,
        num_authorities: 2,
        num_additionals: 3,
    };

    // Write the header bytes to a buffer.
    let mut buffer = vec![];
    header_to_bytes(&original_header, &mut buffer)?;

    // Parse the header bytes from the buffer.
    let mut cursor = Cursor::new(buffer.as_ref());
    let parsed_header = parse_dns_header(&mut cursor)?;

    // Ensure we got the original header after parsing the header bytes.
    assert_eq!(original_header, parsed_header);

    Ok(())
}

fn parse_dns_question(reader: &mut Cursor<&[u8]>) -> Result<DNSQuestion> {
    let name = decode_dns_name(reader)?;
    let record_type = reader.read_u16::<byteorder::BigEndian>()?;
    let record_class = reader.read_u16::<byteorder::BigEndian>()?;
    Ok(DNSQuestion {
        name,
        r#type: RecordType::from(record_type),
        class: RecordClass::from(record_class),
    })
}

#[cfg(test)]
#[test]
fn test_parse_dns_question() -> Result<(), Box<dyn std::error::Error>> {
    let original_question = DNSQuestion {
        name: encode_dns_name("www.google.com")?,
        r#type: RecordType::A,
        class: RecordClass::In,
    };

    let mut buffer = vec![];
    question_to_bytes(&original_question, &mut buffer)?;

    let parsed_question = parse_dns_question(&mut Cursor::new(&buffer))?;

    // Expect the original question without the name being encoded.
    // TODO: using encoded and decoded values in the same struct is bad design. Change this.
    let expected_question = DNSQuestion {
        name: b"www.google.com".to_vec(),
        r#type: RecordType::A,
        class: RecordClass::In,
    };
    assert_eq!(expected_question, parsed_question);

    Ok(())
}

fn parse_dns_record(reader: &mut Cursor<&[u8]>) -> Result<DNSRecord> {
    let name = decode_dns_name(reader).context("decoding dns name")?;

    let record_type = reader
        .read_u16::<byteorder::BigEndian>()
        .context("reading record type")?;
    let record_class = reader
        .read_u16::<byteorder::BigEndian>()
        .context("reading record class")?;
    let ttl = reader
        .read_u32::<byteorder::BigEndian>()
        .context("reading record ttl")?;
    let data_len = reader
        .read_u16::<byteorder::BigEndian>()
        .context("reading record data len")?;

    let mut data_buffer = vec![0_u8; data_len as usize];

    reader
        .read_exact(&mut data_buffer)
        .context("reading data into data buffer")?;

    Ok(DNSRecord {
        name,
        r#type: RecordType::from(record_type),
        class: RecordClass::from(record_class),
        ttl,
        data: data_buffer,
    })
}

fn parse_dns_packet(reader: &mut Cursor<&[u8]>) -> Result<DNSPacket> {
    let header = parse_dns_header(reader)?;

    let mut questions = Vec::with_capacity(header.num_questions as usize);
    for _ in 0..header.num_questions {
        questions.push(parse_dns_question(reader)?);
    }

    let mut answers = Vec::with_capacity(header.num_answers as usize);
    for _ in 0..header.num_answers {
        answers.push(parse_dns_record(reader).context("parsing answer")?);
    }
    let mut authorities: Vec<DNSRecord> = Vec::with_capacity(header.num_authorities as usize);
    for _ in 0..header.num_authorities {
        authorities.push(parse_dns_record(reader)?);
    }
    let mut additionals = Vec::with_capacity(header.num_additionals as usize);
    for _ in 0..header.num_additionals {
        additionals.push(parse_dns_record(reader)?);
    }
    Ok(DNSPacket {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

#[cfg(test)]
#[test]
fn test_parse_dns_packet() {}

pub async fn send_query(
    ip_address: &str,
    domain_name: &str,
    record_type: RecordType,
) -> Result<DNSPacket> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding udp socket")?;

    let query = build_query(rand::thread_rng().gen(), domain_name, record_type)?;

    // 53 is the dns port.
    let bytes_sent = socket
        .send_to(&query, ip_address)
        .await
        .context("sending message to target address")?;
    if bytes_sent != query.len() {
        return Err(anyhow!("unable to write all query bytes to socket",));
    }

    let mut buffer = [0_u8; 1024];
    let (bytes_read, _addr) = socket.recv_from(&mut buffer).await?;

    let received = &buffer[0..bytes_read];

    parse_dns_packet(&mut Cursor::new(received)).context("parsing dns packet")
}

/// Resolves a domain name to its ip address.
// TODO: could allocate less here but i'm tired.
pub async fn resolve(domain_name: &str, record_type: RecordType) -> Result<IpAddr> {
    let root_server = "198.41.0.4:53".to_string();

    let mut name_server = root_server;

    loop {
        let dns_packet = send_query(&name_server, domain_name, record_type)
            .await
            .context("sending query to name server")?;

        if let Some(a_record) = dns_packet
            .answers
            .into_iter()
            .find(|answer| answer.r#type == record_type)
        {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                a_record.data[0],
                a_record.data[1],
                a_record.data[2],
                a_record.data[3],
            )));
        }

        if let Some(record) = dns_packet
            .additionals
            .iter()
            .find(|additional| additional.r#type == RecordType::A)
        {
            name_server = format!(
                "{}.{}.{}.{}:53",
                record.data[0], record.data[1], record.data[2], record.data[3]
            );
        } else if let Some(record) = dns_packet
            .authorities
            .into_iter()
            .find(|authority| authority.r#type == RecordType::NS)
        {
            let ns_domain =
                String::from_utf8(record.data).context("transforming ns record data in String")?;

            name_server = format!("{ns_domain}:53");
        } else {
            return Err(anyhow!("unable to find domain name address"));
        }
    }
}

#[cfg(test)]
#[ignore]
#[tokio::test]
async fn test_resolve() -> Result<(), Box<dyn std::error::Error>> {
    let ip = resolve("www.metafilter.com", RecordType::A).await?;

    dbg!(ip);

    Ok(())
}
