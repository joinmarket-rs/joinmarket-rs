use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use joinmarket_core::handshake::{
    DnHandshake, HandshakeError, PeerHandshake, CURRENT_PROTO_VER, dn_supported_features,
};
use joinmarket_core::message::{
    OnionEnvelope, msg_type,
    parse_pubmsg_line, parse_privmsg_line,
    JmMessage, MessageCommand,
};
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_tor::provider::{BoxReader, BoxWriter};

use crate::router::{
    MakerInfo, Router, SendResult, SupportedFeatures, TakerInfo, PEER_CHANNEL_CAPACITY,
};
use crate::admission::AdmissionController;

/// Python JoinMarket uses MAX_LENGTH = 40000 in its LineReceiver.
const MAX_LINE_LEN: usize = 40_000;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Maximum pubmsg broadcasts a single peer may send per 60-second window.
const MAX_PUBMSG_PER_MINUTE: usize = 30;
/// Separate, tighter per-peer cap for `!orderbook` commands (taker → DN).
/// The Python client sends one on connect and one after each coinjoin, so 3/min
/// is already generous while preventing amplification attacks on makers.
const MAX_ORDERBOOK_PER_MINUTE: usize = 3;
/// Per-peer cap on GETPEERLIST requests.  Each response can be up to ~1.4 MB
/// (20 k makers × 70 bytes) and requires locking all 64 registry shards, so
/// even a few requests per second from many peers is a significant DoS vector.
const MAX_GETPEERLIST_PER_MINUTE: usize = 3;
/// Per-peer cap on PING frames.  The heartbeat loop sends at most one PING per
/// sweep interval; a legitimate client never sends them manually.
const MAX_PING_PER_MINUTE: usize = 6;
/// Maximum bytes of raw peer input included in a single log message.
/// Prevents log-injection/flooding when an adversary sends oversized or crafted
/// input that would otherwise be echoed verbatim into warn-level log lines.
const MAX_LOG_FIELD_BYTES: usize = 256;

/// Per-peer rate-limiting state threaded through `handle_message`.
/// Grouping all deques into a single struct keeps the function argument count
/// within clippy's 7-argument limit.
struct RateLimitState {
    pubmsg_timestamps:      std::collections::VecDeque<Instant>,
    orderbook_timestamps:   std::collections::VecDeque<Instant>,
    getpeerlist_timestamps: std::collections::VecDeque<Instant>,
    ping_timestamps:        std::collections::VecDeque<Instant>,
}

/// Truncate a string slice to at most `max_bytes` bytes at a valid UTF-8
/// boundary.  Used to cap the size of peer-supplied data before it is written
/// to log output, preventing log-injection and log-flooding.
fn truncate_for_log(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    // Walk back to a char boundary so we don't slice mid-codepoint.
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Read a `\n`-terminated line from a buffered reader without allocating beyond
/// `max_len` bytes. Returns `Ok(n)` where `n` is the number of bytes read
/// (0 = EOF). Returns an I/O error if the line exceeds `max_len`.
async fn read_line_bounded(
    reader: &mut BufReader<BoxReader>,
    buf: &mut String,
    raw: &mut Vec<u8>,
    max_len: usize,
) -> std::io::Result<usize> {
    buf.clear();
    raw.clear();
    // Accumulate raw bytes before converting to UTF-8.  Converting each
    // `fill_buf` chunk individually would reject valid multi-byte sequences
    // that happen to be split across two consecutive `fill_buf` windows
    // (e.g. a 3-byte character returned as 2 bytes then 1 byte).  Deferring
    // the conversion until the newline is found (or EOF) avoids that.
    // The caller owns `raw` and reuses it across calls so no allocation
    // occurs on the hot path once the buffer has reached its working size.
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF — convert and flush whatever was accumulated
            if !raw.is_empty() {
                let s = std::str::from_utf8(raw)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                buf.push_str(s);
            }
            return Ok(total);
        }
        let newline_pos = available.iter().position(|&b| b == b'\n');
        let end = newline_pos.map(|p| p + 1).unwrap_or(available.len());
        total += end;
        if total > max_len {
            reader.consume(end);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line exceeds maximum length",
            ));
        }
        raw.extend_from_slice(&available[..end]);
        reader.consume(end);
        if newline_pos.is_some() {
            let s = std::str::from_utf8(raw)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            buf.push_str(s);
            return Ok(total);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerRole {
    Maker,
    Taker,
}

/// Shared, read-only context for all peer tasks. Created once in the accept
/// loop and wrapped in `Arc` to avoid per-connection `String::clone()`.
pub struct PeerContext {
    pub router: Arc<Router>,
    pub admission: Arc<AdmissionController>,
    pub network: Arc<str>,
    pub motd: Arc<str>,
    pub directory_onion: Arc<str>,
    pub directory_nick: Arc<str>,
}


/// Write an envelope to a peer connection and log the exchange at TRACE level.
/// Enable with `RUST_LOG=joinmarket_dn=trace` to see every sent/received message.
///
/// Each call flushes the writer immediately.  This keeps the implementation
/// simple and correct (the peer sees every message without delay), at the cost
/// of one syscall per message.  JoinMarket message rates are low enough (a few
/// per second per peer at peak) that batching is unnecessary.
async fn send_envelope(
    writer: &mut BufWriter<BoxWriter>,
    nick: &str,
    env: &OnionEnvelope,
) -> anyhow::Result<()> {
    tracing::trace!(nick = %nick, msg_type = env.msg_type, line = %env.line, "send");
    let bytes = env.serialize();
    writer.write_all(bytes.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn handle_peer(
    reader: BoxReader,
    writer: BoxWriter,
    ctx: Arc<PeerContext>,
    shutdown: CancellationToken,
) {
    let router = &ctx.router;
    let admission = &ctx.admission;
    let network = &ctx.network;
    let motd = &ctx.motd;
    let directory_onion = &ctx.directory_onion;
    let directory_nick = &ctx.directory_nick;
    let mut reader = BufReader::with_capacity(4096, reader);
    let mut writer = BufWriter::with_capacity(4096, writer);

    // Single line/byte buffers reused for the handshake read and every
    // subsequent message-loop read. Declaring them here avoids two separate
    // Vec allocations and makes the reuse intent explicit.
    let mut line = String::new();
    let mut raw_buf: Vec<u8> = Vec::new();

    // Step 1: Read peer's handshake — peer sends FIRST (type=793)
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        read_line_bounded(&mut reader, &mut line, &mut raw_buf, MAX_LINE_LEN),
    ).await;

    match handshake_result {
        Ok(Ok(n)) if n > 0 => {}
        Ok(Ok(_)) => {
            tracing::debug!("Peer disconnected during handshake");
            metrics::counter!("jm_handshakes_total", "result" => "eof").increment(1);
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!("Handshake read error: {}", e);
            metrics::counter!("jm_handshakes_total", "result" => "error").increment(1);
            return;
        }
        Err(_) => {
            tracing::warn!("Handshake timeout");
            metrics::counter!("jm_handshakes_total", "result" => "timeout").increment(1);
            return;
        }
    };

    // Parse outer envelope
    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

    let envelope = match OnionEnvelope::parse(trimmed) {
        Ok(e) => e,
        Err(e) => {
            // Truncate raw input before logging to prevent log-injection/flooding.
            tracing::warn!("Invalid handshake envelope JSON: {} (raw: {:?})", e, truncate_for_log(trimmed, MAX_LOG_FIELD_BYTES));
            metrics::counter!("jm_handshakes_total", "result" => "parse_error").increment(1);
            return;
        }
    };

    tracing::trace!(msg_type = envelope.msg_type, line = %envelope.line, "recv handshake");

    if envelope.msg_type != msg_type::HANDSHAKE {
        tracing::warn!(
            "Expected handshake type {}, got {}",
            msg_type::HANDSHAKE, envelope.msg_type
        );
        metrics::counter!("jm_handshakes_total", "result" => "parse_error").increment(1);
        return;
    }

    // Parse peer's handshake from the envelope's line field
    let peer_handshake = match PeerHandshake::parse_json(&envelope.line) {
        Ok(h) => h,
        Err(e) => {
            // Truncate the envelope line before logging to prevent log-injection/flooding.
            tracing::warn!("Invalid peer handshake JSON: {} (raw: {:?})", e, truncate_for_log(&envelope.line, MAX_LOG_FIELD_BYTES));
            metrics::counter!("jm_handshakes_total", "result" => "parse_error").increment(1);
            return;
        }
    };

    // Validate handshake and extract parsed onion address (if any)
    let validated_onion = match peer_handshake.validate(network) {
        Ok(onion) => onion,
        Err(e) => {
            tracing::warn!(
                nick = %peer_handshake.nick,
                error = %e,
                "Handshake validation failed"
            );
            match &e {
                HandshakeError::InvalidOnionAddress(_) => {
                    // Silent disconnect — per spec, a malformed location-string gets
                    // no response; the connection is simply closed.
                    metrics::counter!("jm_admission_invalid_onion_total").increment(1);
                }
                HandshakeError::WrongAppName(_) => {
                    metrics::counter!("jm_handshakes_total", "result" => "wrong_app_name").increment(1);
                    let _ = send_dn_handshake(&mut writer, directory_nick, &peer_handshake.nick, directory_onion, network, motd, false).await;
                }
                HandshakeError::ProtoVerMismatch { .. } => {
                    metrics::counter!("jm_handshakes_total", "result" => "proto_mismatch").increment(1);
                    let _ = send_dn_handshake(&mut writer, directory_nick, &peer_handshake.nick, directory_onion, network, motd, false).await;
                }
                HandshakeError::NetworkMismatch { .. } => {
                    metrics::counter!("jm_handshakes_total", "result" => "network_mismatch").increment(1);
                    let _ = send_dn_handshake(&mut writer, directory_nick, &peer_handshake.nick, directory_onion, network, motd, false).await;
                }
                HandshakeError::DirectoryNotAccepted => {
                    // Silent disconnect — directory nodes cannot register as peers.
                    metrics::counter!("jm_handshakes_total", "result" => "directory_rejected").increment(1);
                }
                HandshakeError::MalformedNick => {
                    // Silent disconnect.
                    metrics::counter!("jm_handshakes_total", "result" => "malformed_nick").increment(1);
                }
                HandshakeError::FieldTooLong => {
                    // Silent disconnect — field too long is a protocol violation.
                    metrics::counter!("jm_handshakes_total", "result" => "field_too_long").increment(1);
                }
                HandshakeError::TooManyFeatures(_) | HandshakeError::NestedFeatureValue(_) => {
                    // Silent disconnect.
                    metrics::counter!("jm_handshakes_total", "result" => "malformed_features").increment(1);
                }
                HandshakeError::JsonParse(_) => {
                    // Already caught above during `parse_json`; unreachable here, but
                    // listed so the compiler enforces exhaustiveness for any future
                    // `HandshakeError` variants.
                    metrics::counter!("jm_handshakes_total", "result" => "parse_error").increment(1);
                }
            }
            return;
        }
    };

    // Classify peer: Maker has a valid onion address; Taker has None
    let (peer_role, peer_onion) = match validated_onion {
        Some(addr) => (PeerRole::Maker, Some(addr)),
        None => (PeerRole::Taker, None),
    };

    let nick: Arc<str> = peer_handshake.nick.clone().into();
    let is_maker = peer_role == PeerRole::Maker;
    let bond = peer_handshake.fidelity_bond();
    let supported_features = SupportedFeatures::new(peer_handshake.advertised_true_features());

    // Admission control — all peers run layers 1 and 4 (nick uniqueness + capacity);
    // makers additionally run layers 2 and 3 (sybil guard + bond deduplication).
    if let Err(e) = admission.admit_peer(nick.as_ref(), peer_onion.as_ref(), bond.as_ref()) {
        tracing::warn!(nick = %nick, error = %e, "Admission rejected");
        return;
    }

    // Step 2: Send directory's handshake response (type=795) — accepted
    if send_dn_handshake(&mut writer, directory_nick, nick.as_ref(), directory_onion, network, motd, true).await.is_err() {
        tracing::warn!(nick = %nick, "Failed to send DN handshake");
        // Roll back admission: the peer never received the accepted response so
        // it will not try to reconnect as a live session, but its nick slot and
        // capacity counter must be freed so a future reconnect can succeed.
        admission.release_peer(nick.as_ref(), is_maker);
        return;
    }

    // Detect whether the peer supports !ping/!pong heartbeat.
    let ping_capable = supported_features.supports_ping();

    // Create per-peer write channel for directed messages (privmsg relay,
    // peerlist, heartbeat probes).
    let (probe_tx, mut probe_rx) = mpsc::channel::<Arc<str>>(PEER_CHANNEL_CAPACITY);

    // Register all per-peer metadata and role-specific state together to
    // minimise the window where admission has passed but the peer is not yet
    // visible to the router (heartbeat sweeps, privmsg routing, etc.).
    let shutdown_token = CancellationToken::new();
    router.register_peer_meta(
        &nick,
        shutdown_token.clone(),
        probe_tx,
        supported_features,
        is_maker,
    );

    // Register in the role-specific registry.  For makers, `peer_onion` is
    // always `Some` (classification guarantees this), so we can destructure
    // directly without the dead `if let` guard.
    if is_maker {
        // SAFETY: `is_maker` is true only when `validated_onion` was `Some`,
        // so `peer_onion` is guaranteed to be `Some` here.
        let onion = peer_onion.as_ref().expect(
            "BUG: is_maker is true but peer_onion is None; classification invariant violated"
        );
        router.register_maker(MakerInfo {
            nick: nick.clone(),
            onion_address: onion.clone(),
            fidelity_bond: bond.map(Arc::new),
        });
    } else {
        router.register_taker(TakerInfo {
            nick: nick.clone(),
            onion_address: peer_onion.clone(),
        });
    }

    metrics::counter!("jm_handshakes_total", "result" => "ok").increment(1);
    tracing::info!(
        nick = %nick,
        role = ?peer_role,
        ping_capable,
        "Peer connected"
    );

    // Subscribe to the broadcast channel.
    let mut broadcast_rx = router.subscribe();

    // Per-peer rate-limiting state (grouped to stay within clippy's arg limit).
    let mut rate_limits = RateLimitState {
        pubmsg_timestamps:      std::collections::VecDeque::new(),
        orderbook_timestamps:   std::collections::VecDeque::new(),
        getpeerlist_timestamps: std::collections::VecDeque::new(),
        ping_timestamps:        std::collections::VecDeque::new(),
    };

    // Message loop — `line` and `raw_buf` are reused from above.
    loop {
        line.clear();

        tokio::select! {
            result = read_line_bounded(&mut reader, &mut line, &mut raw_buf, MAX_LINE_LEN) => {
                match result {
                    Ok(0) => {
                        tracing::debug!(nick = %nick, "Peer disconnected");
                        break;
                    }
                    Ok(_) => {
                        router.update_last_seen(nick.as_ref());
                        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                        if let Err(e) = handle_message(
                            trimmed,
                            nick.clone(),
                            &peer_onion,
                            router,
                            &mut writer,
                            &mut rate_limits,
                        ).await {
                            tracing::warn!(nick = %nick, error = %e, "Message handling error");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(nick = %nick, error = %e, "Read error");
                        break;
                    }
                }
            }
            result = broadcast_rx.recv() => {
                match result {
                    Ok(bcast) => {
                        // Don't echo broadcasts back to the sender
                        if !bcast.sender_nick.is_empty() && bcast.sender_nick.as_ref() == nick.as_ref() {
                            continue;
                        }
                        tracing::trace!(nick = %nick, raw = %bcast.payload.trim_end_matches(['\r', '\n']), "send broadcast");
                        if writer.write_all(bcast.payload.as_bytes()).await.is_err() {
                            tracing::warn!(nick = %nick, "Broadcast write error");
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(nick = %nick, lagged = n, "Peer lagged on broadcast channel; disconnecting");
                        metrics::counter!("jm_broadcast_lag_evictions_total").increment(1);
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            probe = probe_rx.recv() => {
                match probe {
                    Some(frame) => {
                        tracing::trace!(nick = %nick, raw = %frame.trim_end_matches(['\r', '\n']), "send direct");
                        if let Err(e) = writer.write_all(frame.as_bytes()).await {
                            tracing::debug!(nick = %nick, error = %e, "Write probe failed — peer gone");
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    None => break, // probe channel dropped (router shutdown)
                }
            }
            _ = shutdown_token.cancelled() => {
                tracing::info!(nick = %nick, "Evicted by heartbeat");
                break;
            }
            _ = shutdown.cancelled() => {
                tracing::debug!(nick = %nick, "Peer task stopping for shutdown");
                break;
            }
        }
    }

    // Broadcast disconnect notification before deregistering.
    // Only makers are included — takers are transient and must never appear
    // in PEERLIST responses (including disconnect notifications), per protocol.
    if is_maker {
        if let Some(loc) = router.locate_peer(nick.as_ref()) {
            let mut entries = vec![format!("{};{};D", nick, loc)];
            if let Some((dn_nick, dn_loc)) = router.dn_identity_pair() {
                entries.push(format!("{};{}", dn_nick, dn_loc));
            }
            let env = OnionEnvelope::new(msg_type::PEERLIST, entries.join(","));
            router.broadcast_raw(Arc::from(env.serialize().as_str()));
        }
    }

    // Cleanup — release_peer is always called because admit_peer is now always called.
    router.deregister(nick.as_ref(), is_maker);
    admission.release_peer(nick.as_ref(), is_maker);

    tracing::info!(nick = %nick, "Peer disconnected and deregistered");
}

fn directory_peerlist_features() -> Arc<[Arc<str>]> {
    vec![Arc::<str>::from("peerlist_features"), Arc::<str>::from("ping")].into()
}

fn serialize_peerlist_entry(
    nick: &str,
    location: &str,
    advertised_features: &[Arc<str>],
    include_features: bool,
) -> String {
    let mut entry = format!("{};{}", nick, location);
    if include_features && !advertised_features.is_empty() {
        let suffix = advertised_features
            .iter()
            .map(|feature| feature.as_ref())
            .collect::<Vec<_>>()
            .join("+");
        entry.push_str(";F:");
        entry.push_str(&suffix);
    }
    entry
}

/// Send the directory's type=795 handshake response.
/// `dir_onion` is the bare onion address (without port); the location-string is
/// formatted as `<onion>:<VIRTUAL_PORT>` to match the JoinMarket default port.
async fn send_dn_handshake(
    writer: &mut BufWriter<BoxWriter>,
    dir_nick: &str,
    peer_nick: &str,
    dir_onion: &str,
    network: &str,
    motd: &str,
    accepted: bool,
) -> anyhow::Result<()> {
    let dn_hs = DnHandshake {
        app_name: "joinmarket".to_string(),
        directory: true,
        location_string: format!("{}:{}", dir_onion, crate::VIRTUAL_PORT),
        proto_ver_min: CURRENT_PROTO_VER,
        proto_ver_max: CURRENT_PROTO_VER,
        features: dn_supported_features(),
        accepted,
        nick: dir_nick.to_string(),
        network: network.to_string(),
        motd: motd.to_string(),
    };
    let env = OnionEnvelope::new(msg_type::DN_HANDSHAKE, dn_hs.to_json());
    send_envelope(writer, peer_nick, &env).await
}

async fn handle_message(
    line: &str,
    nick: Arc<str>,
    peer_onion: &Option<OnionServiceAddr>,
    router: &Router,
    writer: &mut BufWriter<BoxWriter>,
    rate_limits: &mut RateLimitState,
) -> anyhow::Result<()> {
    if line.is_empty() {
        return Ok(());
    }

    let envelope = match OnionEnvelope::parse(line) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(nick = %nick, error = %e, "Ignoring invalid envelope");
            return Ok(());
        }
    };

    tracing::trace!(nick = %nick, msg_type = envelope.msg_type, line = %envelope.line, "recv");

    match envelope.msg_type {
        msg_type::PUBMSG => {
            // Line format: "<from_nick>!PUBLIC<body>"
            if let Some((from_nick, body)) = parse_pubmsg_line(&envelope.line) {
                // Validate from_nick matches authenticated nick
                if from_nick != nick.as_ref() {
                    tracing::warn!(
                        nick = %nick,
                        // Truncate: from_nick is peer-controlled and could be up to
                        // MAX_LINE_LEN bytes before the '!' separator.
                        from_nick = %truncate_for_log(from_nick, MAX_LOG_FIELD_BYTES),
                        "pubmsg from_nick mismatch — disconnecting"
                    );
                    return Err(anyhow::anyhow!("pubmsg from_nick spoofing attempt"));
                }

                // Rate-limiting strategy:
                //
                // 1. !orderbook uses its own tighter per-peer bucket (3/min) so
                //    a taker cannot use the full 30/min allowance to hammer makers.
                //
                // 2. All other pubmsgs (including invalid/unparseable ones)
                //    count against the general 30/min bucket.
                let now = Instant::now();

                // Parse the JM message so we can identify !orderbook before
                // choosing which rate-limit bucket to apply.
                let parsed_msg = match JmMessage::parse(body) {
                    Ok(msg) => Some(msg),
                    Err(e) => {
                        tracing::debug!(nick = %nick, error = %e, "Ignoring invalid JM message in pubmsg");
                        None
                    }
                };

                let is_orderbook = parsed_msg.as_ref()
                    .is_some_and(|m| m.command == MessageCommand::Orderbook);

                if is_orderbook {
                    let cutoff = now - Duration::from_secs(60);
                    while rate_limits.orderbook_timestamps.front().is_some_and(|&t| t < cutoff) {
                        rate_limits.orderbook_timestamps.pop_front();
                    }
                    if rate_limits.orderbook_timestamps.len() >= MAX_ORDERBOOK_PER_MINUTE {
                        tracing::warn!(nick = %nick, "!orderbook rate limit exceeded — disconnecting");
                        metrics::counter!("jm_orderbook_rate_limit_disconnects_total").increment(1);
                        return Err(anyhow::anyhow!("!orderbook rate limit exceeded"));
                    }
                    rate_limits.orderbook_timestamps.push_back(now);
                } else {
                    let cutoff = now - Duration::from_secs(60);
                    while rate_limits.pubmsg_timestamps.front().is_some_and(|&t| t < cutoff) {
                        rate_limits.pubmsg_timestamps.pop_front();
                    }
                    if rate_limits.pubmsg_timestamps.len() >= MAX_PUBMSG_PER_MINUTE {
                        tracing::warn!(nick = %nick, "Pubmsg rate limit exceeded — disconnecting");
                        metrics::counter!("jm_pubmsg_rate_limit_disconnects_total").increment(1);
                        return Err(anyhow::anyhow!("pubmsg broadcast rate limit exceeded"));
                    }
                    rate_limits.pubmsg_timestamps.push_back(now);
                }

                if parsed_msg.is_some() {
                    broadcast_pubmsg(&nick, body, router);
                }
            } else {
                tracing::debug!(nick = %nick, "Ignoring malformed pubmsg line");
            }
        }

        msg_type::PRIVMSG => {
            // Line format: "<from_nick>!<to_nick>!<body>"
            if let Some((from_nick, to_nick, _body)) = parse_privmsg_line(&envelope.line) {
                // Validate from_nick matches authenticated nick
                if from_nick != nick.as_ref() {
                    tracing::warn!(
                        nick = %nick,
                        // Truncate: from_nick is peer-controlled and could be up to
                        // MAX_LINE_LEN bytes before the first '!' separator.
                        from_nick = %truncate_for_log(from_nick, MAX_LOG_FIELD_BYTES),
                        "privmsg from_nick mismatch — disconnecting"
                    );
                    return Err(anyhow::anyhow!("privmsg from_nick spoofing attempt"));
                }
                dispatch_privmsg(&envelope.line, to_nick, nick.clone(), peer_onion, router).await?;
            }
        }

        msg_type::GETPEERLIST => {
            // Rate-limit: each response serialises up to ~1.4 MB and locks all 64
            // registry shards; unrestricted flooding is a significant DoS vector.
            let now = Instant::now();
            let cutoff = now - Duration::from_secs(60);
            while rate_limits.getpeerlist_timestamps.front().is_some_and(|&t| t < cutoff) {
                rate_limits.getpeerlist_timestamps.pop_front();
            }
            if rate_limits.getpeerlist_timestamps.len() >= MAX_GETPEERLIST_PER_MINUTE {
                tracing::warn!(nick = %nick, "GETPEERLIST rate limit exceeded — disconnecting");
                metrics::counter!("jm_getpeerlist_rate_limit_disconnects_total").increment(1);
                return Err(anyhow::anyhow!("GETPEERLIST rate limit exceeded"));
            }
            rate_limits.getpeerlist_timestamps.push_back(now);

            let response = router.get_peers_response();
            let include_features = router.peer_supports_peerlist_features(nick.as_ref());
            let mut entries: Vec<String> = Vec::with_capacity(response.peers.len() + 1);
            // Include DN itself (Python DN always includes itself in the peerlist)
            if let Some((dn_nick, dn_loc)) = router.dn_identity_pair() {
                let dn_features = directory_peerlist_features();
                entries.push(serialize_peerlist_entry(
                    dn_nick.as_ref(),
                    dn_loc.as_ref(),
                    dn_features.as_ref(),
                    include_features,
                ));
            }
            for maker in &response.peers {
                let advertised_features = router.peer_advertised_features(maker.nick.as_ref())
                    .unwrap_or_else(|| Arc::<[Arc<str>]>::from([]));
                entries.push(serialize_peerlist_entry(
                    maker.nick.as_ref(),
                    maker.onion_address.as_location_string().as_str(),
                    advertised_features.as_ref(),
                    include_features,
                ));
            }
            let peerlist_body = entries.join(",");
            let env = OnionEnvelope::new(msg_type::PEERLIST, peerlist_body);
            send_envelope(writer, nick.as_ref(), &env).await?;
        }

        msg_type::PING => {
            // Rate-limit PING to prevent a peer from forcing a busy-loop of
            // allocate→serialise→flush cycles that starve the broadcast select arm.
            let now = Instant::now();
            let cutoff = now - Duration::from_secs(60);
            while rate_limits.ping_timestamps.front().is_some_and(|&t| t < cutoff) {
                rate_limits.ping_timestamps.pop_front();
            }
            if rate_limits.ping_timestamps.len() >= MAX_PING_PER_MINUTE {
                tracing::warn!(nick = %nick, "PING rate limit exceeded — disconnecting");
                metrics::counter!("jm_ping_rate_limit_disconnects_total").increment(1);
                return Err(anyhow::anyhow!("PING rate limit exceeded"));
            }
            rate_limits.ping_timestamps.push_back(now);

            let env = OnionEnvelope::new(msg_type::PONG, "");
            send_envelope(writer, nick.as_ref(), &env).await?;
        }

        msg_type::PONG => {
            router.record_pong(nick.as_ref());
            tracing::debug!(nick = %nick, "Received pong");
        }

        msg_type::DISCONNECT => {
            return Err(anyhow::anyhow!("Peer requested disconnect"));
        }

        other => {
            tracing::debug!(nick = %nick, msg_type = other, "Ignoring unhandled message type");
        }
    }

    Ok(())
}

/// Serialise and broadcast a public message to all connected peers.
fn broadcast_pubmsg(nick: &Arc<str>, body: &str, router: &Router) {
    let pubmsg_line = format!("{}!PUBLIC{}", nick, body);
    let broadcast_msg: Arc<str> = OnionEnvelope::new(msg_type::PUBMSG, pubmsg_line).serialize().into();
    router.broadcast(nick.as_ref(), broadcast_msg);
}


/// Relay a private message to the target peer and send the sender's location info.
/// The Python DN forwards ALL privmsgs (not just fill/ioauth/txsigs).
async fn dispatch_privmsg(
    original_line: &str,
    to_nick: &str,
    from_nick: Arc<str>,
    from_onion: &Option<OnionServiceAddr>,
    router: &Router,
) -> anyhow::Result<()> {
    // 1. Forward the original privmsg envelope to the target peer
    let fwd_env = OnionEnvelope::new(msg_type::PRIVMSG, original_line);
    let fwd_bytes: Arc<str> = Arc::from(fwd_env.serialize().as_str());
    match router.send_to_peer(to_nick, fwd_bytes) {
        SendResult::Ok => {
            metrics::counter!("jm_router_locate_hits_total").increment(1);
        }
        SendResult::ChannelFull => {
            metrics::counter!("jm_router_privmsg_channel_full_total").increment(1);
            tracing::warn!(
                from = %from_nick,
                target = %to_nick,
                "Privmsg dropped: target peer channel full (backpressure)"
            );
            return Ok(());
        }
        SendResult::NotFound => {
            // Don't count messages directed at the DN's own nick as routing misses;
            // these are expected privmsg replies to heartbeat !orderbook probes.
            if router.dn_nick().is_none_or(|n| n.as_ref() != to_nick) {
                metrics::counter!("jm_router_locate_misses_total").increment(1);
                tracing::debug!(
                    from = %from_nick,
                    target = %to_nick,
                    "Target peer not found for privmsg relay"
                );
            }
            return Ok(());
        }
    }

    // 2. Send a peerlist (type=789) with the sender's location to the target,
    //    so they can connect directly. Include the DN itself.
    if let Some(ref onion) = from_onion {
        let include_features = router.peer_supports_peerlist_features(to_nick);
        let sender_features = router.peer_advertised_features(from_nick.as_ref())
            .unwrap_or_else(|| Arc::<[Arc<str>]>::from([]));
        let mut entries = vec![
            serialize_peerlist_entry(
                from_nick.as_ref(),
                onion.as_location_string().as_str(),
                sender_features.as_ref(),
                include_features,
            ),
        ];
        if let Some((dn_nick, dn_loc)) = router.dn_identity_pair() {
            let dn_features = directory_peerlist_features();
            entries.push(serialize_peerlist_entry(
                dn_nick.as_ref(),
                dn_loc.as_ref(),
                dn_features.as_ref(),
                include_features,
            ));
        }
        let peerlist_env = OnionEnvelope::new(msg_type::PEERLIST, entries.join(","));
        let peerlist_bytes: Arc<str> = Arc::from(peerlist_env.serialize().as_str());
        if let SendResult::ChannelFull = router.send_to_peer(to_nick, peerlist_bytes) {
            tracing::warn!(
                from = %from_nick,
                target = %to_nick,
                "Peerlist after privmsg dropped: target peer channel full"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_peerlist_entry_legacy_omits_features() {
        let features: Arc<[Arc<str>]> = vec![Arc::<str>::from("ping")].into();
        assert_eq!(
            serialize_peerlist_entry("J5nickOOOOOOOOOO", "abc.onion:5222", features.as_ref(), false),
            "J5nickOOOOOOOOOO;abc.onion:5222"
        );
    }

    #[test]
    fn test_serialize_peerlist_entry_extended_preserves_sorted_features() {
        let features: Arc<[Arc<str>]> = vec![
            Arc::<str>::from("peerlist_features"),
            Arc::<str>::from("ping"),
            Arc::<str>::from("weird"),
        ].into();
        assert_eq!(
            serialize_peerlist_entry("J5nickOOOOOOOOOO", "abc.onion:5222", features.as_ref(), true),
            "J5nickOOOOOOOOOO;abc.onion:5222;F:peerlist_features+ping+weird"
        );
    }

    #[test]
    fn test_directory_peerlist_features_are_static() {
        assert_eq!(
            directory_peerlist_features().iter().map(|f| f.as_ref()).collect::<Vec<_>>(),
            vec!["peerlist_features", "ping"]
        );
    }
}
