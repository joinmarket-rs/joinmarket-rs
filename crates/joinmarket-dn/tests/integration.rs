//! Integration tests for the JoinMarket directory node.
//!
//! These tests spin up the server in-process using `MockTorProvider` and
//! connect mock peers to exercise the full handshake → message loop path.
//!
//! Wire protocol: every message is wrapped in `{"type": N, "line": "..."}` + `\r\n`.
//! The peer sends its handshake (type=793) FIRST; the directory responds (type=795).

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use joinmarket_dn::{admission, router, server};
use joinmarket_core::handshake::CURRENT_PROTO_VER;
use joinmarket_core::message::{OnionEnvelope, msg_type};
use joinmarket_tor::mock::MockTorProvider;

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
const MAKER_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:5222";

/// All nicks must be exactly 16 chars, start with 'J', and have valid base58 in pos 2+.
const NICK_MAKER: &str = "J5testMakerOOOOO";  // 16 chars
const NICK_TAKER: &str = "J5testTakerOOOOO";  // 16 chars
const NICK_MAKER_A: &str = "J5makerNickOOOOO"; // 16 chars
const NICK_TAKER_A: &str = "J5takerNickOOOOO"; // 16 chars
const NICK_PING: &str    = "J5pingTakerOOOOO"; // 16 chars
const NICK_BAD: &str     = "J5badNickOOOOOOO"; // 16 chars (used where nick doesn't matter)
const NICK_DISC: &str    = "J5discMakerOOOOO"; // 16 chars

/// Spawn a test server and return (mock_provider, router, shutdown_token).
async fn start_test_server() -> (Arc<MockTorProvider>, Arc<router::Router>, CancellationToken) {
    let tor = Arc::new(MockTorProvider::new(TEST_ONION).await.unwrap());
    let r = Arc::new(router::Router::new());
    let adm = Arc::new(admission::AdmissionController::new());
    let shutdown = CancellationToken::new();

    let tor_clone = tor.clone();
    let r_clone = r.clone();
    let adm_clone = adm.clone();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        server::run_accept_loop(
            tor_clone,
            r_clone,
            adm_clone,
            "mainnet".to_string(),
            "test motd".to_string(),
            shutdown_clone,
        ).await.ok();
    });

    // Brief pause to let the accept loop start
    tokio::time::sleep(Duration::from_millis(20)).await;

    (tor, r, shutdown)
}

/// Connect a TCP client to the mock server's local port.
async fn connect_to_server(
    tor: &MockTorProvider,
) -> (BufReader<tokio::io::ReadHalf<TcpStream>>, tokio::io::WriteHalf<TcpStream>) {
    let stream = TcpStream::connect(format!("127.0.0.1:{}", tor.local_port())).await.unwrap();
    let (r, w) = tokio::io::split(stream);
    (BufReader::new(r), w)
}

/// Read the next line (terminated by `\n`) with a 3-second timeout.
/// Returns the raw string including the trailing newline.
async fn read_raw_line(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Option<String> {
    let mut line = String::new();
    let result = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await;
    match result {
        Ok(Ok(0)) | Err(_) => None,
        Ok(Ok(_)) => Some(line),
        Ok(Err(_)) => None,
    }
}

/// Read a line and parse it as an `OnionEnvelope`. Returns None on timeout/EOF/parse error.
async fn read_envelope(reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>) -> Option<OnionEnvelope> {
    let line = read_raw_line(reader).await?;
    OnionEnvelope::parse(line.trim_end()).ok()
}

/// Build a peer handshake JSON string (inner payload, not yet envelope-wrapped).
fn peer_handshake_json(nick: &str, location_string: &str) -> String {
    format!(
        "{{\"app-name\":\"joinmarket\",\"directory\":false,\
         \"location-string\":\"{location_string}\",\
         \"proto-ver\":5,\"features\":{{}},\"nick\":\"{nick}\",\
         \"network\":\"mainnet\"}}"
    )
}

/// Wrap a payload JSON string in a type=793 envelope and append `\r\n`.
fn wrap_in_handshake_envelope(payload_json: &str) -> String {
    OnionEnvelope::new(msg_type::HANDSHAKE, payload_json).serialize()
}

/// Send the peer's handshake (type=793) and read the directory's response (type=795).
/// Returns the directory's DnHandshake envelope.
async fn do_handshake(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    nick: &str,
    location_string: &str,
) -> OnionEnvelope {
    // Peer sends first
    let hs_json = peer_handshake_json(nick, location_string);
    let envelope = wrap_in_handshake_envelope(&hs_json);
    writer.write_all(envelope.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    // Read directory's type=795 response
    read_envelope(reader).await.expect("expected DN handshake response (type=795)")
}

/// Maker handshake: has a location-string → registered as maker.
async fn maker_handshake(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    nick: &str,
) -> OnionEnvelope {
    do_handshake(reader, writer, nick, MAKER_ONION).await
}

/// Taker handshake: empty location-string → registered as taker.
async fn taker_handshake(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    nick: &str,
) -> OnionEnvelope {
    do_handshake(reader, writer, nick, "").await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_handshake_maker_registers() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    let dn_resp = maker_handshake(&mut reader, &mut writer, NICK_MAKER).await;

    assert_eq!(dn_resp.msg_type, msg_type::DN_HANDSHAKE);
    assert!(dn_resp.line.contains("\"accepted\":true"), "DN response: {}", dn_resp.line);

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(router.maker_count(), 1);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_handshake_taker_registers() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    let dn_resp = taker_handshake(&mut reader, &mut writer, NICK_TAKER).await;

    assert_eq!(dn_resp.msg_type, msg_type::DN_HANDSHAKE);
    assert!(dn_resp.line.contains("\"accepted\":true"), "DN response: {}", dn_resp.line);

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 1);

    shutdown.cancel();
}

#[tokio::test]
async fn test_getpeers_returns_only_makers() {
    let (tor, _router, shutdown) = start_test_server().await;

    // Connect maker
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER_A).await;

    // Connect taker
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER_A).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Taker sends getpeerlist (type=791)
    let req = OnionEnvelope::new(msg_type::GETPEERLIST, "").serialize();
    taker_w.write_all(req.as_bytes()).await.unwrap();
    taker_w.flush().await.unwrap();

    // Read peerlist (type=789) response
    let response = read_envelope(&mut taker_r).await.expect("expected peerlist response");
    assert_eq!(response.msg_type, msg_type::PEERLIST, "expected peerlist, got: {:?}", response);
    assert!(response.line.contains(NICK_MAKER_A), "maker should be in peers response: {}", response.line);
    assert!(!response.line.contains(NICK_TAKER_A), "taker should NOT be in peers response: {}", response.line);

    shutdown.cancel();
}

#[tokio::test]
async fn test_ann_broadcast_to_all_peers() {
    let (tor, _router, shutdown) = start_test_server().await;

    // Connect a maker (sender)
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER).await;

    // Connect a taker (receiver) — different nick, no onion → no sybil conflict
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Maker sends !sw0absoffer as pubmsg (type=687)
    // Line format: "<nick>!PUBLIC<body>"
    let ann_line = format!("{}!PUBLIC!sw0absoffer hello from maker", NICK_MAKER);
    let ann_env = OnionEnvelope::new(msg_type::PUBMSG, ann_line).serialize();
    maker_w.write_all(ann_env.as_bytes()).await.unwrap();
    maker_w.flush().await.unwrap();

    // Taker should receive the broadcast (also type=687)
    let broadcast = read_envelope(&mut taker_r).await.expect("expected broadcast message");
    assert_eq!(broadcast.msg_type, msg_type::PUBMSG);
    assert!(broadcast.line.contains("!sw0absoffer hello from maker"), "got: {}", broadcast.line);

    shutdown.cancel();
}

#[tokio::test]
async fn test_ping_pong() {
    let (tor, _router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    taker_handshake(&mut reader, &mut writer, NICK_PING).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Send ping (type=797), expect pong (type=799)
    let ping = OnionEnvelope::new(msg_type::PING, "").serialize();
    writer.write_all(ping.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let pong = read_envelope(&mut reader).await.expect("expected pong");
    assert_eq!(pong.msg_type, msg_type::PONG, "expected pong, got: {:?}", pong);

    shutdown.cancel();
}

#[tokio::test]
async fn test_invalid_onion_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (_reader, mut writer) = connect_to_server(&tor).await;

    // Peer with an invalid onion address in the location-string
    let bad_hs_json = format!(
        "{{\"app-name\":\"joinmarket\",\"directory\":false,\
         \"location-string\":\"notavalidonion.onion:5222\",\
         \"proto-ver\":5,\"features\":{{}},\"nick\":\"{NICK_BAD}\",\
         \"network\":\"mainnet\"}}"
    );
    let envelope = wrap_in_handshake_envelope(&bad_hs_json);
    writer.write_all(envelope.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Peer should be rejected (not registered as maker)
    assert_eq!(router.maker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_wrong_network_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    let wrong_net_json = format!(
        "{{\"app-name\":\"joinmarket\",\"directory\":false,\
         \"location-string\":\"{MAKER_ONION}\",\
         \"proto-ver\":5,\"features\":{{}},\"nick\":\"{NICK_BAD}\",\
         \"network\":\"signet\"}}"
    );
    let envelope = wrap_in_handshake_envelope(&wrong_net_json);
    writer.write_all(envelope.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    // Read the rejected response before checking
    let _ = read_envelope(&mut reader).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_deregister_on_disconnect() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    maker_handshake(&mut reader, &mut writer, NICK_DISC).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(router.maker_count(), 1);

    // Drop the connection — server should detect EOF and deregister
    drop(writer);
    drop(reader);

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(router.maker_count(), 0);

    shutdown.cancel();
}

// ── New tests for protocol compatibility fixes ──────────────────────────────

const NICK_MAKER_B: &str = "J5makerBBBBOOOOO"; // 16 chars
const NICK_TAKER_B: &str = "J5takerBBBBOOOOO"; // 16 chars
const NICK_NOT_SERVING: &str = "J5notServOOOOOOO"; // 16 chars

#[tokio::test]
async fn test_not_serving_onion_taker() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    // Use "NOT-SERVING-ONION" as location-string (Python client sentinel value)
    let dn_resp = do_handshake(&mut reader, &mut writer, NICK_NOT_SERVING, "NOT-SERVING-ONION").await;

    assert_eq!(dn_resp.msg_type, msg_type::DN_HANDSHAKE);
    assert!(dn_resp.line.contains("\"accepted\":true"), "DN response: {}", dn_resp.line);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Should register as taker (not maker)
    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 1);

    shutdown.cancel();
}

#[tokio::test]
async fn test_broadcast_does_not_echo_to_sender() {
    let (tor, _router, shutdown) = start_test_server().await;

    // Connect a maker (sender)
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER_B).await;

    // Connect a taker (receiver)
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER_B).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Maker sends !sw0absoffer
    let ann_line = format!("{}!PUBLIC!sw0absoffer test echo filter", NICK_MAKER_B);
    let ann_env = OnionEnvelope::new(msg_type::PUBMSG, ann_line).serialize();
    maker_w.write_all(ann_env.as_bytes()).await.unwrap();
    maker_w.flush().await.unwrap();

    // Taker should receive the broadcast
    let taker_msg = read_envelope(&mut taker_r).await.expect("taker should receive broadcast");
    assert_eq!(taker_msg.msg_type, msg_type::PUBMSG);
    assert!(taker_msg.line.contains("!sw0absoffer test echo filter"));

    // Maker should NOT receive the broadcast back (echo filtering).
    // Use a short timeout — if we get nothing, the filter is working.
    let maker_msg = tokio::time::timeout(
        Duration::from_millis(500),
        read_envelope(&mut maker_r),
    ).await;
    assert!(maker_msg.is_err() || maker_msg.unwrap().is_none(),
        "Maker should NOT receive its own broadcast back");

    shutdown.cancel();
}

#[tokio::test]
async fn test_peerlist_format_comma_separated() {
    let (tor, _router, shutdown) = start_test_server().await;

    // Connect maker
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER_A).await;

    // Connect taker
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER_A).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Taker sends getpeerlist
    let req = OnionEnvelope::new(msg_type::GETPEERLIST, "").serialize();
    taker_w.write_all(req.as_bytes()).await.unwrap();
    taker_w.flush().await.unwrap();

    let response = read_envelope(&mut taker_r).await.expect("expected peerlist");
    assert_eq!(response.msg_type, msg_type::PEERLIST);

    // Verify comma-separated format with ';' separator between nick and location
    // Format: "dn_nick;dn_loc,maker_nick;maker_loc"
    let entries: Vec<&str> = response.line.split(',').collect();
    assert!(entries.len() >= 2, "expected at least DN + 1 maker, got: {}", response.line);

    // Each entry should have "nick;location" format
    for entry in &entries {
        let parts: Vec<&str> = entry.split(';').collect();
        assert!(parts.len() >= 2, "entry should have nick;location format: {}", entry);
    }

    // The maker should be present
    assert!(response.line.contains(NICK_MAKER_A), "maker nick missing: {}", response.line);
    assert!(response.line.contains(MAKER_ONION), "maker onion missing: {}", response.line);

    // Taker should NOT be in peerlist
    assert!(!response.line.contains(NICK_TAKER_A), "taker should not be in peerlist: {}", response.line);

    shutdown.cancel();
}

#[tokio::test]
async fn test_privmsg_forwarded_to_target() {
    let (tor, _router, shutdown) = start_test_server().await;

    // Connect maker (target)
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER_A).await;

    // Connect taker (sender)
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER_A).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Taker sends a privmsg to maker: "<from>!<to>!<body>"
    let privmsg_line = format!("{}!{}!!fill 1000000 abc", NICK_TAKER_A, NICK_MAKER_A);
    let privmsg_env = OnionEnvelope::new(msg_type::PRIVMSG, privmsg_line).serialize();
    taker_w.write_all(privmsg_env.as_bytes()).await.unwrap();
    taker_w.flush().await.unwrap();

    // Maker should receive the forwarded privmsg (type=685)
    let maker_msg = read_envelope(&mut maker_r).await.expect("maker should receive privmsg");
    assert_eq!(maker_msg.msg_type, msg_type::PRIVMSG, "expected PRIVMSG type, got: {:?}", maker_msg);
    assert!(maker_msg.line.contains("!fill 1000000 abc"), "privmsg body missing: {}", maker_msg.line);
    assert!(maker_msg.line.contains(NICK_TAKER_A), "sender nick missing: {}", maker_msg.line);

    shutdown.cancel();
}

#[tokio::test]
async fn test_disconnect_notification() {
    let (tor, router, shutdown) = start_test_server().await;

    // Connect maker (will disconnect)
    let (mut maker_r, mut maker_w) = connect_to_server(&tor).await;
    maker_handshake(&mut maker_r, &mut maker_w, NICK_MAKER_A).await;

    // Connect taker (observer)
    let (mut taker_r, mut taker_w) = connect_to_server(&tor).await;
    taker_handshake(&mut taker_r, &mut taker_w, NICK_TAKER_A).await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(router.maker_count(), 1);

    // Drop the maker connection
    drop(maker_w);
    drop(maker_r);

    // Taker should receive a disconnect notification (type=789 peerlist with ";D" suffix)
    let disconnect_msg = read_envelope(&mut taker_r).await.expect("taker should receive disconnect notification");
    assert_eq!(disconnect_msg.msg_type, msg_type::PEERLIST, "expected PEERLIST disconnect notification, got: {:?}", disconnect_msg);
    assert!(disconnect_msg.line.contains(";D"), "disconnect entry should have ;D suffix: {}", disconnect_msg.line);
    assert!(disconnect_msg.line.contains(NICK_MAKER_A), "disconnect should reference maker nick: {}", disconnect_msg.line);

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(router.maker_count(), 0);

    shutdown.cancel();
}

// ── Security remediation tests ──────────────────────────────────────────────

const NICK_SPOOF: &str  = "J5spoofNickOOOOO"; // 16 chars
const NICK_VICTIM: &str = "J5victimNkOOOOOO"; // 16 chars

#[tokio::test]
async fn test_oversized_handshake_line_rejected() {
    let (tor, router, shutdown) = start_test_server().await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", tor.local_port())).await.unwrap();
    let (_, mut writer) = tokio::io::split(stream);

    // Send a line exceeding MAX_LINE_LEN (40,000 bytes) without a newline
    let big_payload = "A".repeat(50_000);
    writer.write_all(big_payload.as_bytes()).await.unwrap();
    writer.write_all(b"\n").await.unwrap();
    writer.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_pubmsg_from_nick_mismatch_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    // Connect a taker
    let (mut reader, mut writer) = connect_to_server(&tor).await;
    taker_handshake(&mut reader, &mut writer, NICK_SPOOF).await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(router.taker_count(), 1);

    // Send a pubmsg claiming to be from a DIFFERENT nick
    let spoofed_line = format!("{}!PUBLIC!sw0absoffer spoofed message", NICK_VICTIM);
    let env = OnionEnvelope::new(msg_type::PUBMSG, spoofed_line).serialize();
    writer.write_all(env.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    // Should be disconnected for nick mismatch
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(router.taker_count(), 0, "spoofing peer should be disconnected");

    shutdown.cancel();
}

#[tokio::test]
async fn test_privmsg_from_nick_mismatch_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    // Connect a taker
    let (mut reader, mut writer) = connect_to_server(&tor).await;
    taker_handshake(&mut reader, &mut writer, NICK_SPOOF).await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(router.taker_count(), 1);

    // Send a privmsg with a spoofed from_nick
    let spoofed_line = format!("{}!{}!!fill 1000000", NICK_VICTIM, NICK_MAKER_A);
    let env = OnionEnvelope::new(msg_type::PRIVMSG, spoofed_line).serialize();
    writer.write_all(env.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(router.taker_count(), 0, "spoofing peer should be disconnected");

    shutdown.cancel();
}

// ── Handshake edge-case tests ───────────────────────────────────────────────

const NICK_EDGE: &str = "J5edgeCaseOOOOOO"; // 16 chars

/// Build a raw handshake JSON with arbitrary field overrides.
fn custom_handshake_json(
    app_name: &str,
    directory: bool,
    location_string: &str,
    proto_ver: u32,
    nick: &str,
    network: &str,
) -> String {
    format!(
        "{{\"app-name\":\"{app_name}\",\"directory\":{directory},\
         \"location-string\":\"{location_string}\",\
         \"proto-ver\":{proto_ver},\"features\":{{}},\"nick\":\"{nick}\",\
         \"network\":\"{network}\"}}"
    )
}

/// Helper: send a custom handshake envelope and return whatever the server
/// sends back (if anything within 2 s).  Returns `None` on timeout / EOF.
async fn send_custom_handshake(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    payload_json: &str,
) -> Option<OnionEnvelope> {
    let envelope = wrap_in_handshake_envelope(payload_json);
    writer.write_all(envelope.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), read_envelope(reader))
        .await
        .ok()
        .flatten()
}



#[tokio::test]
async fn test_wrong_app_name_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    let hs = custom_handshake_json(
        "WrongApp", false, MAKER_ONION, 5, NICK_EDGE, "mainnet",
    );
    let _resp = send_custom_handshake(&mut reader, &mut writer, &hs).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0, "wrong app-name peer should not be a maker");
    assert_eq!(router.taker_count(), 0, "wrong app-name peer should not be a taker");

    shutdown.cancel();
}

#[tokio::test]
async fn test_proto_ver_too_old_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    let hs = custom_handshake_json(
        "joinmarket", false, MAKER_ONION, (CURRENT_PROTO_VER - 1) as u32, NICK_EDGE, "mainnet",
    );
    let resp = send_custom_handshake(&mut reader, &mut writer, &hs).await;

    // Server may send a rejected response before closing
    if let Some(env) = resp {
        assert!(
            env.line.contains("\"accepted\":false"),
            "expected rejected handshake, got: {}", env.line
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_proto_ver_too_new_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    let hs = custom_handshake_json(
        "joinmarket", false, MAKER_ONION, (CURRENT_PROTO_VER as u32) + 1, NICK_EDGE, "mainnet",
    );
    let resp = send_custom_handshake(&mut reader, &mut writer, &hs).await;

    if let Some(env) = resp {
        assert!(
            env.line.contains("\"accepted\":false"),
            "expected rejected handshake, got: {}", env.line
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_directory_flag_rejected() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    // Peer claims to be a directory node
    let hs = custom_handshake_json(
        "joinmarket", true, MAKER_ONION, 5, NICK_EDGE, "mainnet",
    );
    let _resp = send_custom_handshake(&mut reader, &mut writer, &hs).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Directory-to-directory connections must be rejected
    assert_eq!(router.maker_count(), 0, "directory peer should not be registered as maker");
    assert_eq!(router.taker_count(), 0, "directory peer should not be registered as taker");

    shutdown.cancel();
}

#[tokio::test]
async fn test_missing_handshake_fields_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    // JSON with only app-name and proto-ver — missing nick, network, etc.
    let incomplete_json = r#"{"app-name":"joinmarket","proto-ver":5}"#;
    let _resp = send_custom_handshake(&mut reader, &mut writer, incomplete_json).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_invalid_json_handshake_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    let (_reader, mut writer) = connect_to_server(&tor).await;

    // Send a valid envelope but with garbage (non-JSON) as the inner payload
    let garbage_envelope = OnionEnvelope::new(
        msg_type::HANDSHAKE, "this is not json at all",
    ).serialize();
    writer.write_all(garbage_envelope.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_lenient_location_string_treated_as_taker() {
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;

    // Bare port number — some legacy/buggy clients send this.
    // It is not a valid onion address, so the peer should either be treated
    // as a taker (lenient) or disconnected (strict). Both are acceptable as
    // long as it is NEVER registered as a maker.
    let hs = custom_handshake_json(
        "joinmarket", false, "9050", 5, NICK_EDGE, "mainnet",
    );
    let resp = send_custom_handshake(&mut reader, &mut writer, &hs).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    match resp {
        Some(env) if env.line.contains("\"accepted\":true") => {
            // Lenient path: accepted as taker
            assert_eq!(router.taker_count(), 1, "lenient: should be registered as taker");
        }
        _ => {
            // Strict path: disconnected
            assert_eq!(router.taker_count(), 0);
        }
    }

    // Invariant either way: must NEVER be a maker.
    assert_eq!(router.maker_count(), 0, "malformed location must not produce a maker");

    shutdown.cancel();
}

#[tokio::test]
async fn test_handshake_timeout_disconnects() {
    let (tor, router, shutdown) = start_test_server().await;

    // Connect but never send anything — server should time out after 10 s
    let (_reader, _writer) = connect_to_server(&tor).await;

    // Wait longer than the 10-second handshake timeout
    tokio::time::sleep(Duration::from_secs(12)).await;

    // The silent peer must not be registered
    assert_eq!(router.maker_count(), 0);
    assert_eq!(router.taker_count(), 0);

    shutdown.cancel();
}

#[tokio::test]
async fn test_not_serving_onion_accepted_as_taker() {
    // Complements test_not_serving_onion_taker by also verifying the DN
    // response explicitly contains "accepted":true.
    let (tor, router, shutdown) = start_test_server().await;

    let (mut reader, mut writer) = connect_to_server(&tor).await;
    let dn_resp = do_handshake(
        &mut reader, &mut writer, NICK_EDGE, "NOT-SERVING-ONION",
    ).await;

    assert_eq!(dn_resp.msg_type, msg_type::DN_HANDSHAKE);
    assert!(
        dn_resp.line.contains("\"accepted\":true"),
        "NOT-SERVING-ONION should be accepted, got: {}", dn_resp.line
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(router.maker_count(), 0, "NOT-SERVING-ONION must not register as maker");
    assert_eq!(router.taker_count(), 1, "NOT-SERVING-ONION should register as taker");

    shutdown.cancel();
}
