//! The small part of HTTP/1.1 the proxy reads, and what it does to bytes on the way through.

use std::io::{self, BufRead, Read, Write};

const MAX_LINE: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;

pub(super) fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let joined = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(joined >> 18) as usize & 63] as char);
        out.push(TABLE[(joined >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(joined >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[joined as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub(super) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes = text.trim().as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|byte| **byte == b'=').count();
        let mut joined = 0u32;
        for byte in &chunk[..4 - pad] {
            joined = (joined << 6) | value(*byte)?;
        }
        joined <<= 6 * pad as u32;
        out.push((joined >> 16) as u8);
        if pad < 2 {
            out.push((joined >> 8) as u8);
        }
        if pad < 1 {
            out.push(joined as u8);
        }
    }
    Some(out)
}

/// Replaces a value in a stream, holding back enough bytes that one split across reads is still found.
pub(super) struct Scrubber {
    needle: Vec<u8>,
    with: Vec<u8>,
    held: Vec<u8>,
}

impl Scrubber {
    pub(super) fn new(real: &str, stand_in: &str) -> Self {
        // A reply's length was counted with the real value in it. A stand-in of another length, such as one
        // for an OAuth access token, is cut or filled to that length, so the framing still holds.
        let mut with = stand_in.as_bytes().to_vec();
        with.resize(real.len(), b'x');
        Self {
            needle: real.as_bytes().to_vec(),
            with,
            held: Vec::new(),
        }
    }

    pub(super) fn push(&mut self, data: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(data);
        let mut out = Vec::with_capacity(self.held.len());
        let mut at = 0;
        while let Some(found) = self.held[at..]
            .windows(self.needle.len())
            .position(|window| window == self.needle)
        {
            out.extend_from_slice(&self.held[at..at + found]);
            out.extend_from_slice(&self.with);
            at += found + self.needle.len();
        }
        // Only what could still become the value waits. Anything else goes now, or a tool that sends a
        // little and waits for an answer would wait forever.
        let rest = &self.held[at..];
        let longest = self.needle.len().saturating_sub(1).min(rest.len());
        let keep = (0..=longest)
            .rev()
            .find(|count| rest[rest.len() - count..] == self.needle[..*count])
            .unwrap_or(0);
        let flush_to = self.held.len() - keep;
        out.extend_from_slice(&self.held[at..flush_to]);
        self.held.drain(..flush_to);
        out
    }

    pub(super) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// Many servers end without a TLS goodbye, once they have said it all.
struct EndIsEnd<R>(R);

impl<R: Read> Read for EndIsEnd<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self.0.read(into) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

/// Sends a reply on with the key scrubbed, and gives back its status. The framing of a chunked reply
/// could split the key in two, so it is read through the chunks and chunked again. The end marker goes
/// out only if the reply really ended, so a cut reply still looks cut.
pub(super) fn relay_reply(
    from: impl Read,
    to: &mut impl Write,
    scrub: &mut Scrubber,
) -> io::Result<u16> {
    let mut from = io::BufReader::new(EndIsEnd(from));
    // A 103 or 100 comes before the real answer, whose head is the one that says how its body is framed.
    let mut status;
    let mut chunked;
    loop {
        let Some(first) = read_line_capped(&mut from)? else {
            return Ok(0);
        };
        status = status_of(first.as_bytes());
        chunked = false;
        let mut head = format!("{first}\r\n");
        let mut count = 0;
        let ended = loop {
            let Some(line) = read_line_capped(&mut from)? else {
                break false;
            };
            count += 1;
            if count > MAX_HEADERS {
                return Err(io::Error::other("too many headers"));
            }
            chunked |= line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
            });
            head.push_str(&line);
            head.push_str("\r\n");
            if line.is_empty() {
                break true;
            }
        };
        to.write_all(&scrub.push(head.as_bytes()))?;
        // The head is done, so what is still held back must leave before any chunk frames it.
        to.write_all(&scrub.finish())?;
        if !ended {
            return Ok(status);
        }
        if !(100..200).contains(&status) || status == 101 {
            break;
        }
        to.flush()?;
    }
    let mut buffer = vec![0u8; 16 * 1024];
    if !chunked {
        loop {
            let count = from.read(&mut buffer)?;
            if count == 0 {
                to.write_all(&scrub.finish())?;
                return Ok(status);
            }
            to.write_all(&scrub.push(&buffer[..count]))?;
        }
    }
    let mut write_chunk = |data: &[u8]| -> io::Result<()> {
        // A chunk of nothing would say the reply is over.
        if !data.is_empty() {
            write!(to, "{:x}\r\n", data.len())?;
            to.write_all(data)?;
            to.write_all(b"\r\n")?;
            to.flush()?;
        }
        Ok(())
    };
    loop {
        let Some(line) = read_line_capped(&mut from)? else {
            return Ok(status);
        };
        let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| io::Error::other("a bad chunk"))?;
        if size == 0 {
            break;
        }
        let mut left = size;
        while left > 0 {
            let wanted = buffer
                .len()
                .min(usize::try_from(left).unwrap_or(buffer.len()));
            let count = from.read(&mut buffer[..wanted])?;
            if count == 0 {
                return Ok(status);
            }
            write_chunk(&scrub.push(&buffer[..count]))?;
            left -= count as u64;
        }
        if read_line_capped(&mut from)?.is_none_or(|end| !end.is_empty()) {
            return Ok(status);
        }
    }
    write_chunk(&scrub.finish())?;
    to.write_all(b"0\r\n\r\n")?;
    Ok(status)
}

pub(super) fn status_of(head: &[u8]) -> u16 {
    std::str::from_utf8(&head[..head.len().min(16)])
        .ok()
        .and_then(|text| text.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

pub(super) fn answer(to: &mut impl Write, status: u16, text: &str) -> io::Result<()> {
    write!(
        to,
        "HTTP/1.1 {status} keyreeve\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )?;
    to.flush()
}

pub(super) fn split_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_ascii_lowercase(), port))
}

pub(super) fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(super) fn read_line_capped(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                None
            } else {
                Some(String::from_utf8(line).map_err(io::Error::other)?)
            });
        }
        let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.len() > MAX_LINE {
            return Err(io::Error::other("a line is too long"));
        }
        if done {
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            return Ok(Some(String::from_utf8(line).map_err(io::Error::other)?));
        }
    }
}

pub(super) fn read_head(reader: &mut impl BufRead) -> io::Result<(String, Vec<(String, String)>)> {
    let first = read_line_capped(reader)?.ok_or_else(|| io::Error::other("no request"))?;
    let mut headers = Vec::new();
    loop {
        let line = read_line_capped(reader)?.ok_or_else(|| io::Error::other("the head was cut"))?;
        if line.is_empty() {
            return Ok((first, headers));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(io::Error::other("too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("a header has no name"))?;
        // A folded or spaced name is how one request gets read as two.
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(io::Error::other("a header has a bad name"));
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
}

pub(super) enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// Two ways to say where a body ends, or two different lengths, is how a request gets smuggled.
pub(super) fn body_framing(headers: &[(String, String)]) -> Result<Framing, ()> {
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .collect();
    match (header(headers, "transfer-encoding"), lengths.as_slice()) {
        (None, []) => Ok(Framing::None),
        (None, [one]) => one.parse().map(Framing::Length).map_err(|_| ()),
        (Some(value), []) if value.eq_ignore_ascii_case("chunked") => Ok(Framing::Chunked),
        _ => Err(()),
    }
}

pub(super) fn copy_body(
    framing: &Framing,
    from: &mut impl BufRead,
    to: &mut impl Write,
) -> io::Result<()> {
    match framing {
        Framing::None => Ok(()),
        Framing::Length(count) => {
            let copied = io::copy(&mut from.by_ref().take(*count), to)?;
            if copied == *count {
                Ok(())
            } else {
                Err(io::Error::other("the body was cut"))
            }
        }
        Framing::Chunked => loop {
            let line =
                read_line_capped(from)?.ok_or_else(|| io::Error::other("the body was cut"))?;
            write!(to, "{line}\r\n")?;
            let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::Error::other("a bad chunk"))?;
            if size == 0 {
                loop {
                    let trailer = read_line_capped(from)?
                        .ok_or_else(|| io::Error::other("the body was cut"))?;
                    write!(to, "{trailer}\r\n")?;
                    if trailer.is_empty() {
                        return Ok(());
                    }
                }
            }
            let copied = io::copy(&mut from.by_ref().take(size), to)?;
            if copied != size {
                return Err(io::Error::other("the body was cut"));
            }
            let end =
                read_line_capped(from)?.ok_or_else(|| io::Error::other("the body was cut"))?;
            if !end.is_empty() {
                return Err(io::Error::other("a bad chunk"));
            }
            to.write_all(b"\r\n")?;
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relayed(reply: &str) -> (Vec<u8>, u16) {
        let mut out = Vec::new();
        let mut scrub = Scrubber::new("real-key-0123456789", "fake-key-9876543210");
        let status = relay_reply(reply.as_bytes(), &mut out, &mut scrub).unwrap();
        (out, status)
    }

    fn text(out: &[u8]) -> String {
        String::from_utf8(out.to_vec()).unwrap()
    }

    #[test]
    fn a_key_split_across_chunks_is_still_found() {
        let (out, status) = relayed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nreal-key-\r\na\r\n0123456789\r\n0\r\n\r\n",
        );
        assert_eq!(status, 200);
        let body = text(&out);
        assert!(!body.contains("real-key"), "{body}");
        assert!(!body.contains("0123456789"), "{body}");
        let framed = body.split("\r\n\r\n").nth(1).unwrap();
        assert!(framed.contains("fake-key-9876543210"), "{body}");
        assert!(body.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn a_chunked_reply_is_still_valid_chunks() {
        let (out, _) = relayed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let body = text(&out);
        let (_, framed) = body.split_once("\r\n\r\n").unwrap();
        let mut rest = framed;
        let mut joined = String::new();
        loop {
            let (size, after) = rest.split_once("\r\n").unwrap();
            let size = usize::from_str_radix(size, 16).unwrap();
            if size == 0 {
                break;
            }
            joined.push_str(&after[..size]);
            rest = &after[size + 2..];
        }
        assert_eq!(joined, "hello world");
    }

    #[test]
    fn a_cut_reply_does_not_get_an_ending() {
        let (out, _) =
            relayed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n9\r\nabc");
        assert!(!text(&out).ends_with("0\r\n\r\n"));
    }

    #[test]
    fn an_early_hint_does_not_hide_how_the_real_reply_is_framed() {
        let (out, status) = relayed(
            "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nreal-key-\r\na\r\n0123456789\r\n0\r\n\r\n",
        );
        assert_eq!(status, 200);
        let body = text(&out);
        assert!(!body.contains("0123456789"), "{body}");
        assert!(body.contains("fake-key-9876543210"), "{body}");
    }

    #[test]
    fn a_reply_with_endless_headers_is_stopped() {
        let mut reply = String::from("HTTP/1.1 200 OK\r\n");
        for number in 0..(MAX_HEADERS + 2) {
            reply.push_str(&format!("X-{number}: a\r\n"));
        }
        let mut scrub = Scrubber::new("real-key-0123456789", "fake-key-9876543210");
        assert!(relay_reply(reply.as_bytes(), &mut Vec::new(), &mut scrub).is_err());
    }

    #[test]
    fn what_cannot_become_the_key_is_not_held_back() {
        let mut scrub = Scrubber::new("real-key-0123456789", "fake-key-9876543210");
        assert_eq!(scrub.push(b"hello"), b"hello");
        assert_eq!(scrub.push(b"then real-k"), b"then ");
        assert_eq!(scrub.push(b"ind"), b"real-kind");
        assert_eq!(scrub.push(b"real-key-012345678"), b"");
        assert_eq!(scrub.push(b"9!"), b"fake-key-9876543210!");
    }

    #[test]
    fn a_plain_reply_is_scrubbed_in_head_and_body() {
        let (out, _) = relayed(
            "HTTP/1.1 200 OK\r\nX-Key: real-key-0123456789\r\nContent-Length: 19\r\n\r\nreal-key-0123456789",
        );
        let body = text(&out);
        assert!(!body.contains("real-key"), "{body}");
        assert_eq!(body.matches("fake-key-9876543210").count(), 2);
    }

    #[test]
    fn a_reply_with_no_end_of_head_loses_nothing() {
        let (out, status) = relayed("HTTP/1.1 500 Oops\r\nX-Key: real-key-0123456789\r\n");
        assert_eq!(status, 500);
        assert!(text(&out).contains("fake-key-9876543210"));
    }
}
