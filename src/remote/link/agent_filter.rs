//! SSH agent protocol filter for dial-in agent forwarding: frames (u32
//! big-endian length plus a type byte) are bounded, and only
//! `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST` reach the
//! hub user's agent; every other request is answered `SSH_AGENT_FAILURE`.

use std::io::{self, Read, Write};

/// Largest accepted frame body, as OpenSSH's `MAX_AGENT_REPLY_LEN`.
pub(crate) const MAX_FRAME_BYTES: usize = 256 * 1024;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const FAILURE_FRAME: [u8; 5] = [0, 0, 0, 1, SSH_AGENT_FAILURE];

/// Reads one frame, length prefix included. `None` on end-of-file before
/// its first byte; an empty, oversized, or truncated frame is an error.
fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SSH agent frame of {length} bytes is outside 1..={MAX_FRAME_BYTES}"),
        ));
    }
    let mut frame = vec![0_u8; header.len() + length];
    frame[..header.len()].copy_from_slice(&header);
    reader.read_exact(&mut frame[header.len()..])?;
    Ok(Some(frame))
}

fn is_allowed(frame: &[u8]) -> bool {
    matches!(
        frame.get(4),
        Some(&(SSH_AGENTC_REQUEST_IDENTITIES | SSH_AGENTC_SIGN_REQUEST))
    )
}

/// Serves requests from `client` one at a time until it closes: allowed
/// requests are forwarded to `agent` and its one reply is returned; every
/// other request is answered with `SSH_AGENT_FAILURE` without contacting
/// the agent. Malformed frames from either side end the session, and so
/// does an allowed request that `authorize` (asked before each one) refuses.
pub(crate) fn filter_requests(
    client_in: &mut impl Read,
    client_out: &mut impl Write,
    agent: &mut (impl Read + Write),
    mut authorize: impl FnMut() -> bool,
) -> io::Result<()> {
    while let Some(request) = read_frame(client_in)? {
        if is_allowed(&request) {
            if !authorize() {
                return Ok(());
            }
            agent.write_all(&request)?;
            agent.flush()?;
            let reply = read_frame(agent)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the SSH agent closed the connection",
                )
            })?;
            client_out.write_all(&reply)?;
        } else {
            client_out.write_all(&FAILURE_FRAME)?;
        }
        client_out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = ((body.len() + 1) as u32).to_be_bytes().to_vec();
        frame.push(kind);
        frame.extend_from_slice(body);
        frame
    }

    /// Records what it receives and answers from canned replies.
    struct FakeAgent {
        received: Vec<u8>,
        replies: Cursor<Vec<u8>>,
    }

    impl FakeAgent {
        fn new(replies: Vec<u8>) -> Self {
            Self {
                received: Vec::new(),
                replies: Cursor::new(replies),
            }
        }
    }

    impl Read for FakeAgent {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.replies.read(buffer)
        }
    }

    impl Write for FakeAgent {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.received.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn run(requests: Vec<u8>, agent: &mut FakeAgent) -> (io::Result<()>, Vec<u8>) {
        let mut output = Vec::new();
        let result = filter_requests(&mut Cursor::new(requests), &mut output, agent, || true);
        (result, output)
    }

    #[test]
    fn a_revoked_authorization_ends_the_session_before_the_agent() {
        let identities = frame(12, b"\0\0\0\0");
        let requests = [frame(11, b""), frame(19, b""), frame(13, b"key+data")].concat();
        let mut agent = FakeAgent::new(identities.clone());
        let mut output = Vec::new();
        let mut checks = 0;
        let authorize = || {
            checks += 1;
            checks == 1
        };
        filter_requests(
            &mut Cursor::new(requests),
            &mut output,
            &mut agent,
            authorize,
        )
        .unwrap();
        // Only the first listing reached the agent; the refused request was
        // answered locally without a check; the signing request ended it.
        assert_eq!(checks, 2);
        assert_eq!(agent.received, frame(11, b""));
        assert_eq!(output, [identities, FAILURE_FRAME.to_vec()].concat());
    }

    #[test]
    fn only_identity_listing_and_signing_reach_the_agent() {
        let identities = frame(12, b"\0\0\0\0");
        let signature = frame(14, b"sig");
        let mut requests = Vec::new();
        let mut forwarded = Vec::new();
        let mut expected = Vec::new();
        // add, remove, remove all, lock, unlock, add constrained, extension
        // (session-bind), protocol 1 listing: answered locally.
        for kind in [17, 18, 19, 22, 23, 25, 27, 1] {
            requests.extend(frame(kind, b"payload"));
            expected.extend(FAILURE_FRAME);
        }
        for (request, reply) in [
            (frame(11, b""), &identities),
            (frame(13, b"key+data"), &signature),
        ] {
            requests.extend(&request);
            forwarded.extend(request);
            expected.extend(reply);
        }
        let mut agent = FakeAgent::new([identities.clone(), signature.clone()].concat());
        let (result, output) = run(requests, &mut agent);
        result.unwrap();
        assert_eq!(agent.received, forwarded);
        assert_eq!(output, expected);
    }

    #[test]
    fn malformed_frames_end_the_session_without_reaching_the_agent() {
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
        let empty = 0_u32.to_be_bytes().to_vec();
        let truncated_body = frame(11, b"abc")[..6].to_vec();
        let truncated_header = vec![0, 0];
        for (requests, kind) in [
            (oversized, io::ErrorKind::InvalidData),
            (empty, io::ErrorKind::InvalidData),
            (truncated_body, io::ErrorKind::UnexpectedEof),
            (truncated_header, io::ErrorKind::UnexpectedEof),
        ] {
            let mut agent = FakeAgent::new(Vec::new());
            let (result, output) = run(requests.clone(), &mut agent);
            assert_eq!(result.unwrap_err().kind(), kind, "{requests:?}");
            assert!(agent.received.is_empty() && output.is_empty());
        }
        // The largest allowed frame passes; a clean end of input is not an error.
        let largest = frame(13, &vec![7; MAX_FRAME_BYTES - 1]);
        let mut agent = FakeAgent::new(frame(5, b""));
        let (result, output) = run(largest.clone(), &mut agent);
        result.unwrap();
        assert_eq!(agent.received, largest);
        assert_eq!(output, FAILURE_FRAME);
        assert!(run(Vec::new(), &mut FakeAgent::new(Vec::new())).0.is_ok());
    }

    #[test]
    fn a_missing_or_malformed_agent_reply_ends_the_session() {
        for (replies, kind) in [
            (Vec::new(), io::ErrorKind::UnexpectedEof),
            (
                ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
                io::ErrorKind::InvalidData,
            ),
        ] {
            let mut agent = FakeAgent::new(replies);
            let (result, output) = run(frame(11, b""), &mut agent);
            assert_eq!(result.unwrap_err().kind(), kind);
            assert!(output.is_empty());
        }
    }
}
