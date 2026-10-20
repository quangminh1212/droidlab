//! DLWP/1 frames on a TCP socket.
//!
//! `droidlab_protocol` turns bytes into [`FrameHeader`]s and [`Value`]s and deliberately knows
//! nothing about sockets, threads or blocking. This module is the smallest thing that can sit on
//! top of it: it reads exactly one frame, writes exactly one frame, and reports every failure as a
//! value.
//!
//! # Why a frame-at-a-time API
//!
//! The obvious design is a `Stream` of frames, and it is the wrong one here. The handshake is a
//! **strict alternation** — `HELLO`, `HELLO_OK`, `AUTH`, `AUTH_OK` — in which each side's next
//! legal message depends on the last one it received. A stream would have to buffer or drop
//! frames that arrive out of turn, and either choice hides a protocol violation instead of
//! reporting it. Reading one frame at a time makes "who speaks next" the caller's problem, which
//! is where the state machine already is.
//!
//! # The two length checks, and why both are needed
//!
//! The header's `body_length` is attacker-controlled: it arrives in cleartext, before any
//! authentication, from a peer that may not be who it claims. So the length is checked twice.
//! First against the largest body any frame is allowed to have, which is a constant, so that a
//! `body_length` of 4 GiB is refused before a single byte is allocated for it. Then against the
//! negotiated session limit once a frame is known to be well-formed, which is policy and belongs
//! to the session rather than to the transport.
//!
//! A read that allocates before it bounds is a denial of service, and the first check exists to
//! make that impossible rather than unlikely.

use std::io;
use std::time::Duration;

use droidlab_protocol::{FrameHeader, Value, FIXED_LENGTH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The largest body this transport will read into memory before authentication.
///
/// 16 MiB. It is not a protocol limit — [`droidlab_protocol::Limits`] owns those and this is
/// deliberately larger than the largest of them, so that a body the session would reject anyway
/// still fails as a *session* verdict with a nameable error code rather than as a transport
/// error with none. Its job is only to be small enough that no single frame can exhaust memory.
pub const MAX_UNTRUSTED_BODY: u32 = 16 * 1024 * 1024;

/// How long a single frame read may take before the peer is considered gone.
///
/// Not a protocol rule. A peer that has sent a header and then stalls holds a task and a socket
/// open indefinitely, and a mirror session that hangs is worse than one that fails, because a
/// failure can be shown to the user.
pub const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything that can go wrong reading a frame from a socket.
///
/// Kept as a value rather than as a panic for the same reason the codec's decode does: this code
/// is reachable from the network, so every failure path must be one the caller can handle.
#[derive(Debug)]
pub enum TransportError {
    /// The socket failed, at either end. The peer is gone or the network is.
    Io(io::Error),
    /// No complete frame arrived within [`FRAME_READ_TIMEOUT`].
    ///
    /// Distinct from [`TransportError::Io`] because a timeout is worth retrying and a reset is
    /// usually not, and the two are indistinguishable once collapsed into an `io::Error`.
    TimedOut,
    /// The peer closed cleanly between frames. This is the normal end of a session and the caller
    /// should not report it as a fault.
    Closed,
    /// The peer announced a body larger than [`MAX_UNTRUSTED_BODY`] and it was refused before
    /// being read.
    BodyTooLarge {
        /// What the peer claimed.
        announced: u32,
        /// What this transport will read.
        maximum: u32,
    },
    /// The header bytes did not parse. The connection is unusable: the reader cannot know where
    /// the next frame starts, so resynchronising is not attempted.
    BadHeader(droidlab_protocol::FrameError),
    /// The body did not parse as cbOR.
    ///
    /// Recoverable in principle — the frame boundary is known — but this transport still ends the
    /// connection, because a body that does not decode means the peer is not speaking DLWP/1 and
    /// continuing would be guessing.
    BadBody(droidlab_protocol::CborError),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket error: {error}"),
            Self::TimedOut => write!(f, "timed out waiting for a frame"),
            Self::Closed => write!(f, "the peer closed the connection"),
            Self::BodyTooLarge { announced, maximum } => write!(
                f,
                "the peer announced a {announced}-byte body, above the {maximum}-byte ceiling"
            ),
            Self::BadHeader(error) => write!(f, "malformed frame header: {error}"),
            Self::BadBody(error) => write!(f, "malformed frame body: {error}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::BadHeader(error) => Some(error),
            Self::BadBody(error) => Some(error),
            Self::TimedOut | Self::Closed | Self::BodyTooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// One decoded frame: its header and its body.
///
/// The header is kept alongside the body rather than merged into it because the sequence number,
/// the channel and the flags are all needed by the session layer after the body has been
/// dispatched, and reconstructing them from the body would be guesswork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The 24-byte header, already parsed and validated.
    pub header: FrameHeader,
    /// The body, already decoded from cbOR. Empty for a message that has no body.
    pub body: Value,
}

impl Frame {
    /// Builds a frame from a header and a body.
    ///
    /// Does not encode anything, and does not check that the two agree — the body length in the
    /// header is set from `body` by [`Frame::encode`], which is the only place that can keep them
    /// consistent.
    #[must_use]
    pub fn new(header: FrameHeader, body: Value) -> Self {
        Self { header, body }
    }

    /// Encodes the frame, setting `body_length` from the encoded body.
    ///
    /// `body_length` is **overwritten** rather than trusted. A caller that constructed a header by
    /// hand and got the length wrong would otherwise send a frame every receiver rejects, and the
    /// header is a local detail of this API rather than something a caller should have to track.
    /// The returned header is the one actually sent, so a caller that needs it — to match an
    /// acknowledgment, say — has the truth rather than its own guess.
    ///
    /// A body that cannot be encoded is a programming error rather than a peer's fault: it means
    /// the caller built a value this codec cannot represent, which no decoded frame can produce.
    /// It is still a `Result` rather than a panic, because this crate forbids panics and because a
    /// caller may be re-encoding a value it received.
    pub fn encode(&self) -> Result<(Vec<u8>, FrameHeader), TransportError> {
        let body_bytes = self.body.encode().map_err(TransportError::BadBody)?;

        // `body_length` is a u32 on the wire. The conversion is checked rather than cast so that a
        // body too large to describe is an error instead of a silent wrap.
        let body_length = u32::try_from(body_bytes.len()).map_err(|_| {
            TransportError::BodyTooLarge {
                announced: u32::MAX,
                maximum: MAX_UNTRUSTED_BODY,
            }
        })?;

        let header = FrameHeader {
            body_length,
            ..self.header
        };

        let mut bytes = Vec::with_capacity(FIXED_LENGTH + body_bytes.len());
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&body_bytes);
        Ok((bytes, header))
    }
}

/// Reads exactly 24 header bytes, telling a clean close apart from a truncated one.
///
/// The distinction matters and `read_exact` alone cannot make it: end-of-stream before any byte of a
/// header is a session ending normally ([`TransportError::Closed`], not an error worth logging),
/// while end-of-stream partway through a header is a truncated message
/// ([`TransportError::Io`]).
///
/// The probe is `read`, which returns however many bytes are available, and only treats a return of
/// zero as a close. Probing by reading a single byte first and then `read_exact` for the rest would
/// be wrong for a frame format whose first byte is part of a magic number: the probe would consume
/// that byte and hand the decoder a header shifted by one, so every frame after the first close
/// check would fail to parse.
async fn read_header<R>(stream: &mut R) -> Result<[u8; FIXED_LENGTH], TransportError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; FIXED_LENGTH];
    let mut filled = 0usize;

    while filled < FIXED_LENGTH {
        // `get_mut` rather than a range index: this crate denies indexing and slicing.
        let Some(rest) = header_bytes.get_mut(filled..) else {
            break;
        };
        let read = stream.read(rest).await?;
        if read == 0 {
            return if filled == 0 {
                Err(TransportError::Closed)
            } else {
                // A short read followed by end-of-stream. Reported as I/O so a caller does not
                // mistake half a header for a finished session.
                Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer closed partway through a frame header",
                )))
            };
        }
        filled = filled.saturating_add(read);
    }

    Ok(header_bytes)
}

/// Decodes a frame body from its cbOR bytes.
///
/// A shared helper rather than a line repeated in three read paths, because the rule it encodes —
/// trailing bytes are an error, not padding — is a rule the vectors depend on for byte-uniqueness,
/// and three copies of it are three chances for one to be relaxed.
fn decode_body(body_bytes: &[u8]) -> Result<Value, TransportError> {
    let mut reader = droidlab_protocol::cbor::Reader::new(body_bytes);
    reader.read_document().map_err(TransportError::BadBody)
}

/// A TCP connection that reads and writes DLWP/1 frames.
///
/// Owns the socket. Not `Clone`: two tasks writing frames on one connection would interleave
/// partially-written frames, which is a corruption the protocol has no way to detect. A caller
/// that needs to write from two places must serialise through the session, which is where the
/// sequence numbers are anyway.
#[derive(Debug)]
pub struct Transport {
    stream: TcpStream,
    peer: std::net::SocketAddr,
}

impl Transport {
    /// Wraps an established socket.
    ///
    /// `TCP_NODELAY` is set here rather than left to the caller. DLWP/1 sends small control frames
    /// — a tap is one frame of a few dozen bytes — and Nagle's algorithm delays exactly those,
    /// adding tens of milliseconds to every input event. Latency matters more than the bandwidth
    /// Nagle would save on a LAN, so it is off.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let peer = stream.peer_addr()?;
        Ok(Self { stream, peer })
    }

    /// Returns the peer's address.
    ///
    /// Recorded at construction rather than read on demand, because a peer that has vanished can
    /// no longer be asked, and a log line about a dead connection needs to name it.
    #[must_use]
    pub fn peer(&self) -> std::net::SocketAddr {
        self.peer
    }

    /// Whether `TCP_NODELAY` is set, for the test that asserts it.
    ///
    /// A test-only accessor rather than a public setting, because the value must not be settable:
    /// [`Transport::new`] turns it on for a reason that is invisible in review, and an accessor
    /// that could also turn it off would be an invitation to.
    #[doc(hidden)]
    #[must_use]
    pub fn nodelay_for_test(&self) -> bool {
        self.stream.nodelay().unwrap_or(false)
    }

    /// Reads exactly one frame.
    ///
    /// Returns [`TransportError::Closed`] on a clean end-of-stream between frames, which is the
    /// normal way a session finishes and should not be logged as an error. A partial frame
    /// followed by end-of-stream is [`TransportError::Io`] instead, because it is a truncated
    /// message rather than a finished one.
    pub async fn read_frame(&mut self) -> Result<Frame, TransportError> {
        let read = tokio::time::timeout(FRAME_READ_TIMEOUT, self.read_frame_inner()).await;
        match read {
            Ok(result) => result,
            Err(_elapsed) => Err(TransportError::TimedOut),
        }
    }

    /// The read itself, without the timeout wrapper, so that the timeout applies to the whole
    /// frame rather than to each of its two halves separately.
    async fn read_frame_inner(&mut self) -> Result<Frame, TransportError> {
        let header_bytes = read_header(&mut self.stream).await?;
        let header = FrameHeader::decode(&header_bytes).map_err(TransportError::BadHeader)?;

        // Refuse an oversized announcement before allocating for it. This is the check that makes
        // an unauthenticated body length harmless.
        if header.body_length > MAX_UNTRUSTED_BODY {
            return Err(TransportError::BodyTooLarge {
                announced: header.body_length,
                maximum: MAX_UNTRUSTED_BODY,
            });
        }

        // A zero-length body is legal and common: `PING`, `AUTH_OK` and several others carry
        // nothing. The canonical empty body is not "no bytes", it is the cbOR encoding of an empty
        // map -- `droidlab_protocol::cbor` owns that rule, so the decoder is still called rather
        // than short-circuited, and a peer that sends genuinely zero bytes is rejected.
        let mut body_bytes = vec![0u8; header.body_length as usize];
        if !body_bytes.is_empty() {
            self.stream.read_exact(&mut body_bytes).await?;
        }

        let body = decode_body(&body_bytes)?;
        Ok(Frame { header, body })
    }

    /// Writes one frame, and flushes it.
    ///
    /// The flush matters: without it a small frame can sit in the write buffer while the peer
    /// waits for it, which is a deadlock in a handshake whose every step waits for the other side.
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<FrameHeader, TransportError> {
        let (bytes, header) = frame.encode()?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(header)
    }

    /// Splits the transport into a reader and a writer sharing one socket.
    ///
    /// Needed because a live session reads and writes concurrently — the agent pushes video while
    /// the controller pushes input — but it is not needed for the handshake, which alternates. It
    /// is offered here rather than exposing the socket so that `TCP_NODELAY` and the frame
    /// boundary discipline cannot be bypassed by a caller that takes the raw stream.
    #[must_use]
    pub fn into_split(self) -> (FrameReader, FrameWriter) {
        let (read_half, write_half) = self.stream.into_split();
        (
            FrameReader {
                stream: read_half,
                peer: self.peer,
            },
            FrameWriter {
                stream: write_half,
                peer: self.peer,
            },
        )
    }
}

/// The reading half of a split [`Transport`].
#[derive(Debug)]
pub struct FrameReader {
    stream: tokio::net::tcp::OwnedReadHalf,
    peer: std::net::SocketAddr,
}

impl FrameReader {
    /// Returns the peer's address, as [`Transport::peer`] does.
    #[must_use]
    pub fn peer(&self) -> std::net::SocketAddr {
        self.peer
    }

    /// Reads exactly one frame, with the same rules as [`Transport::read_frame`].
    pub async fn read_frame(&mut self) -> Result<Frame, TransportError> {
        let read = tokio::time::timeout(FRAME_READ_TIMEOUT, self.read_frame_inner()).await;
        match read {
            Ok(result) => result,
            Err(_elapsed) => Err(TransportError::TimedOut),
        }
    }

    /// The read itself, without the timeout wrapper.
    async fn read_frame_inner(&mut self) -> Result<Frame, TransportError> {
        let header_bytes = read_header(&mut self.stream).await?;
        let header = FrameHeader::decode(&header_bytes).map_err(TransportError::BadHeader)?;

        if header.body_length > MAX_UNTRUSTED_BODY {
            return Err(TransportError::BodyTooLarge {
                announced: header.body_length,
                maximum: MAX_UNTRUSTED_BODY,
            });
        }

        let mut body_bytes = vec![0u8; header.body_length as usize];
        if !body_bytes.is_empty() {
            self.stream.read_exact(&mut body_bytes).await?;
        }

        let body = decode_body(&body_bytes)?;
        Ok(Frame { header, body })
    }
}

/// The writing half of a split [`Transport`].
#[derive(Debug)]
pub struct FrameWriter {
    stream: tokio::net::tcp::OwnedWriteHalf,
    peer: std::net::SocketAddr,
}

impl FrameWriter {
    /// Returns the peer's address, as [`Transport::peer`] does.
    #[must_use]
    pub fn peer(&self) -> std::net::SocketAddr {
        self.peer
    }

    /// Writes one frame and flushes it, with the same rules as [`Transport::write_frame`].
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<FrameHeader, TransportError> {
        let (bytes, header) = frame.encode()?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(header)
    }
}
