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
        Self {
            needle: real.as_bytes().to_vec(),
            with: stand_in.as_bytes().to_vec(),
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
        let keep = self.needle.len().saturating_sub(1);
        let flush_to = self.held.len().saturating_sub(keep).max(at);
        out.extend_from_slice(&self.held[at..flush_to]);
        self.held.drain(..flush_to);
        out
    }

    pub(super) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
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
