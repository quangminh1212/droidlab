//! Tests for the frame transport.
//!
//! These drive a real loopback socket rather than a mock, because the things most likely to be
//! wrong here are the things a mock would not reproduce: a body that arrives in two TCP segments, a
//! peer that announces a body and never sends it, a peer that closes between frames. A fake reader
//! would let all three pass.
//!
//! The tests use `#[tokio::test]` and bind to port 0, so they run in parallel and do not collide.

use droidlab_controller::transport::{Frame, Transport, TransportError, MAX_UNTRUSTED_BODY};
use droidlab_protocol::{FrameHeader, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// A header with the fields a test cares about and zeroes elsewhere.
fn header(message_type: u8, body_length: u32) -> FrameHeader {
    FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type,
        channel_id: 0,
        sequence_number: 0,
        acknowledgment: 0,
        body_length,
    }
}

/// A body that is a map with one text field, which is the shape every DLWP/1 body has.
fn body_with(name: &str, value: &str) -> Value {
    Value::Map(vec![(
        Value::Text(name.to_owned()),
        Value::Text(value.to_owned()),
    )])
}

/// Pairs a connected client transport with the server half's stream, over loopback.
async fn connected_pair() -> (Transport, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback listener for a test should not fail");
    let address = listener
        .local_addr()
        .expect("a bound listener has an address");

    let accept = tokio::spawn(async move {
        let (stream, _peer) = listener
            .accept()
            .await
            .expect("accepting one loopback connection should not fail");
        stream
    });

    let client = TcpStream::connect(address)
        .await
        .expect("connecting to a loopback listener should not fail");
    let server = accept.await.expect("the accept task should not panic");

    (
        Transport::new(client).expect("wrapping a connected socket should not fail"),
        server,
    )
}

#[tokio::test]
async fn a_frame_round_trips_through_a_socket() {
    let (mut client, mut server) = connected_pair().await;

    let sent = Frame::new(header(1, 0), body_with("role", "controller"));
    let _written = client
        .write_frame(&sent)
        .await
        .expect("writing a well-formed frame should succeed");

    // The server side reads raw bytes and re-parses, so both halves of the codec are exercised
    // rather than one writer feeding one reader.
    let mut raw = vec![0u8; 24 + 32];
    let read = tokio::io::AsyncReadExt::read(&mut server, &mut raw)
        .await
        .expect("reading the frame back should succeed");

    let parsed = FrameHeader::decode(&raw[..24]).expect("the header should parse");
    assert_eq!(parsed.message_type, 1);
    assert_eq!(parsed.version, 1);
    assert!(read > 24, "the body should have arrived with the header");
}

#[tokio::test]
async fn body_length_is_set_from_the_body_not_trusted_from_the_caller() {
    let (mut client, _server) = connected_pair().await;

    // A caller that hands in a deliberately wrong length must still produce a frame that a receiver
    // accepts. `encode` overwrites the field, and the returned header is the truth about what was
    // sent rather than an echo of the caller's mistake.
    let lied_about = Frame::new(header(5, 9999), body_with("k", "v"));
    let (bytes, actual) = lied_about
        .encode()
        .expect("encoding a well-formed frame should succeed");

    assert_ne!(actual.body_length, 9999, "the lie must not have survived");
    assert_eq!(
        bytes.len(),
        24 + actual.body_length as usize,
        "the encoded frame must be exactly header plus the announced body"
    );

    let written = client
        .write_frame(&lied_about)
        .await
        .expect("writing should succeed");
    assert_eq!(written.body_length, actual.body_length);
}

#[tokio::test]
async fn an_oversized_announcement_is_refused_before_the_body_is_allocated() {
    // A listener of its own rather than `connected_pair`, because this test needs to write a raw
    // header and then deliberately send nothing more. Reusing the pair helper would leave a
    // transport half unused and the intent unclear.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback listener should not fail");
    let address = listener
        .local_addr()
        .expect("a bound listener has an address");

    let client = TcpStream::connect(address)
        .await
        .expect("connecting should succeed");
    let (mut server, _peer) = listener
        .accept()
        .await
        .expect("accepting should succeed");

    // A header claiming a body far above the ceiling, and then nothing at all. A reader that
    // allocates before checking would try to reserve 16 MiB and then block waiting for bytes that
    // will never come; a reader that checks first returns at once. The test bounds the wait, so a
    // regression in the check order shows up as a timeout rather than as a slow test.
    //
    // The announcement is written by the *accepted* half, because that is the peer of the transport
    // under test. Writing it on `client` and then reading from `client` would be a socket reading
    // its own output, which never arrives -- that wiring mistake is exactly what made this test
    // time out while the transport was already correct.
    let announcement = header(1, MAX_UNTRUSTED_BODY + 1);
    server
        .write_all(&announcement.encode())
        .await
        .expect("writing a header should succeed");

    let mut transport = Transport::new(client).expect("wrapping should succeed");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn(async move { transport.read_frame().await }),
    )
    .await;

    let error = result
        .expect("the reader must not block on an oversized announcement")
        .expect("the task should not panic")
        .expect_err("an oversized body must be an error");

    let TransportError::BodyTooLarge { announced, maximum } = error else {
        unreachable!("expected BodyTooLarge, got {error:?}");
    };
    assert_eq!(announced, MAX_UNTRUSTED_BODY + 1);
    assert_eq!(maximum, MAX_UNTRUSTED_BODY);
}

#[tokio::test]
async fn a_clean_close_between_frames_is_reported_as_closed() {
    let (mut client, server) = connected_pair().await;
    drop(server);

    let error = client
        .read_frame()
        .await
        .expect_err("a closed socket must be an error");

    // `Closed` and `Io` are distinguished on purpose: the first is a session ending normally and
    // the second is a fault. A caller that logs the first as an error trains its users to ignore
    // the log.
    assert!(
        matches!(error, TransportError::Closed),
        "expected Closed, got {error:?}"
    );
}

#[tokio::test]
async fn a_truncated_header_is_an_io_error_not_a_clean_close() {
    let (mut client, mut server) = connected_pair().await;

    // Five bytes of a 24-byte header, then a close. The peer started a frame and did not finish it,
    // which is a fault: reporting it as `Closed` would let a session that was cut off look like one
    // that ended.
    server
        .write_all(&[0u8, 1, 0, 24, 0])
        .await
        .expect("writing a partial header should succeed");
    drop(server);

    let error = client
        .read_frame()
        .await
        .expect_err("a truncated frame must be an error");

    assert!(
        !matches!(error, TransportError::Closed),
        "a truncated frame must not be reported as a clean close"
    );
}

#[tokio::test]
async fn a_body_split_across_two_writes_is_read_as_one_frame() {
    let (mut client, mut server) = connected_pair().await;

    let frame = Frame::new(header(3, 0), body_with("k", "a longer value"));
    let (bytes, _header) = frame.encode().expect("encoding should succeed");

    // The frame arrives in two TCP segments, with the split in the middle of the body. This is what
    // a real network does routinely and what a reader that assumes one read equals one frame gets
    // wrong.
    let split = 24 + 4;
    server
        .write_all(&bytes[..split])
        .await
        .expect("writing the first half should succeed");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    server
        .write_all(&bytes[split..])
        .await
        .expect("writing the second half should succeed");

    let received = client
        .read_frame()
        .await
        .expect("a split frame must still be one frame");

    assert_eq!(received.header.message_type, 3);
    assert_eq!(received.body, body_with("k", "a longer value"));
}

#[tokio::test]
async fn a_malformed_header_is_rejected_as_a_bad_header() {
    let (mut client, mut server) = connected_pair().await;

    // A full 24 bytes, so the read completes, but a bad magic. Reported as `BadHeader` rather than
    // as a body or an IO failure, because the remedy differs: this peer is not speaking DLWP/1 and
    // resynchronising is pointless.
    let mut header_bytes = header(1, 0).encode();
    header_bytes[0] = 0xFF;
    server
        .write_all(&header_bytes)
        .await
        .expect("writing a bad header should succeed");

    let error = client
        .read_frame()
        .await
        .expect_err("a bad magic must be an error");

    assert!(
        matches!(error, TransportError::BadHeader(_)),
        "expected BadHeader, got {error:?}"
    );
}

#[tokio::test]
async fn a_body_that_is_not_cbor_is_rejected_as_a_bad_body() {
    let (mut client, mut server) = connected_pair().await;

    // A header whose body is four bytes of 0xFF. cbOR's major type 7 with a reserved simple value
    // is not a legal document, so the body fails to parse after the frame boundary was already
    // established.
    // `FrameHeader::encode` returns a fixed-size array, since a header is exactly 24 bytes.
    let mut bytes = Vec::from(header(1, 4).encode());
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    server
        .write_all(&bytes)
        .await
        .expect("writing should succeed");

    let error = client
        .read_frame()
        .await
        .expect_err("an unparseable body must be an error");

    assert!(
        matches!(error, TransportError::BadBody(_)),
        "expected BadBody, got {error:?}"
    );
}

#[tokio::test]
async fn the_peer_address_is_recorded_and_is_the_one_that_connected() {
    let (client, _server) = connected_pair().await;

    // Recorded at construction rather than read on demand, so that a log line about a dead
    // connection can still name it. Asserted as non-unspecified rather than against `127.0.0.1`,
    // because the local address is what the OS chose.
    let peer = client.peer();
    assert!(!peer.ip().is_unspecified(), "the peer must be a real address");
    assert_ne!(peer.port(), 0, "the peer must have a real port");
}

#[tokio::test]
async fn nagle_is_disabled_because_input_latency_depends_on_it() {
    let (client, _server) = connected_pair().await;

    // A tap is one small frame. With Nagle on, a small frame waits for either an acknowledgment or
    // enough data to fill a segment, which on a LAN means tens of milliseconds per input event.
    // The setting is asserted here rather than left to chance because it is invisible in review.
    assert!(client.nodelay_for_test(), "TCP_NODELAY must be set");
}

#[tokio::test]
async fn splitting_a_transport_lets_one_half_read_and_the_other_write() {
    let (client, mut server) = connected_pair().await;
    let (mut reader, mut writer) = client.into_split();

    // The split is what a live session needs: the agent pushes video while the controller pushes
    // input. Exercised here so that the two halves are known to share the socket rather than to be
    // an independent pair of buffers.
    let outbound = Frame::new(header(7, 0), body_with("dir", "out"));
    writer
        .write_frame(&outbound)
        .await
        .expect("the writer half should write");

    let from_client = Frame::new(header(8, 0), body_with("dir", "in"));
    let (from_client_bytes, _) = from_client.encode().expect("encoding should succeed");
    server
        .write_all(&from_client_bytes)
        .await
        .expect("the server should write back");

    let received = reader
        .read_frame()
        .await
        .expect("the reader half should read the server's frame");

    assert_eq!(received.header.message_type, 8);
    assert_eq!(reader.peer(), writer.peer());
}
