use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use joinmarket_core::handshake::{PeerHandshake, DnHandshake, HandshakeError, CURRENT_PROTO_VER};
use joinmarket_core::message::{
    OnionEnvelope, msg_type,
    parse_pubmsg_line, parse_privmsg_line,
    JmMessage, MessageCommand,
};
use joinmarket_core::onion::OnionServiceAddr;
use joinmarket_tor::provider::{BoxReader, BoxWriter};

use crate::router::{Router, MakerInfo, TakerInfo};
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

/// Per-peer rate-limiting state threaded through `handle_message`.
/// Grouping both deques into a single struct keeps the function argument count
/// within clippy's 7-argument limit.
struct RateLimitState {
    pubmsg_timestamps: std::collections::VecDeque<Instant>,
    orderbook_timestamps: std::collections::VecDeque<Instant>,
}

/// Read a `\n`-terminated line from a buffered reader without allocating beyond
/// `max_len` bytes. Returns `Ok(n)` where `n` is the number of bytes read
/// (0 = EOF). Returns an I/O error if the line exceeds `max_len`.
async fn read_line_bounded(
    reader: &mut BufReader<BoxReader>,
    buf: &mut String,
    max_len: usize,
) -> std::io::Result<usize> {
    buf.clear();
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
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
        let chunk = std::str::from_utf8(&available[..end])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        buf.push_str(chunk);
        reader.consume(end);
        if newline_pos.is_some() {
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

    // Step 1: Read peer's handshake — peer sends FIRST (type=793)
    let mut line = String::new();
    let handshake_result = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        read_line_bounded(&mut reader, &mut line, MAX_LINE_LEN),
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
            tracing::warn!("Invalid handshake envelope JSON: {} (raw: {:?})", e, trimmed);
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
            tracing::warn!("Invalid peer handshake JSON: {} (raw: {:?})", e, envelope.line);
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

    // Admission control (layers 2, 3, 4) — only for makers (who have an onion addr)
    if let Some(ref onion) = peer_onion {
        if let Err(e) = admission.admit_peer(nick.as_ref(), onion, bond.as_ref()) {
            tracing::warn!(nick = %nick, error = %e, "Admission rejected");
            return;
        }
    }

    // Step 2: Send directory's handshake response (type=795) — accepted
    if send_dn_handshake(&mut writer, directory_nick, nick.as_ref(), directory_onion, network, motd, true).await.is_err() {
        tracing::warn!(nick = %nick, "Failed to send DN handshake");
        return;
    }

    // Detect whether the peer supports !ping/!pong heartbeat.
    let ping_capable = peer_handshake.supports_ping();

    // Create per-peer write channel for heartbeat probes.
    let (probe_tx, mut probe_rx) = mpsc::channel::<Arc<str>>(16);

    // Register in router
    if is_maker {
        if let Some(ref onion) = peer_onion {
            router.register_maker(MakerInfo {
                nick: nick.clone(),
                onion_address: onion.clone(),
                fidelity_bond: bond.map(Arc::new),
            });
        }
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

    // Register all per-peer metadata in a single insertion.
    let shutdown_token = CancellationToken::new();
    router.register_peer_meta(&nick, shutdown_token.clone(), probe_tx, ping_capable, is_maker);

    // Subscribe to the broadcast channel.
    let mut broadcast_rx = router.subscribe();

    // Per-peer broadcast rate-limiting state (grouped to stay within clippy's arg limit).
    let mut rate_limits = RateLimitState {
        pubmsg_timestamps: std::collections::VecDeque::new(),
        orderbook_timestamps: std::collections::VecDeque::new(),
    };

    // Message loop
    let mut line = String::new();
    loop {
        line.clear();

        tokio::select! {
            result = read_line_bounded(&mut reader, &mut line, MAX_LINE_LEN) => {
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

    // Broadcast disconnect notification before deregistering
    if let Some(loc) = router.locate_peer(nick.as_ref()) {
        let dn_nick = router.dn_nick();
        let dn_loc = router.dn_location();
        let disconnect_entry = format!("{};{};D", nick, loc);
        let mut body = disconnect_entry;
        if !dn_nick.is_empty() && !dn_loc.is_empty() {
            body.push(',');
            body.push_str(&format!("{};{}", dn_nick, dn_loc));
        }
        let env = OnionEnvelope::new(msg_type::PEERLIST, body);
        router.broadcast_raw(Arc::from(env.serialize().as_str()));
    }

    // Cleanup
    router.deregister(nick.as_ref());
    if peer_onion.is_some() {
        admission.release_peer(nick.as_ref());
    }

    tracing::info!(nick = %nick, "Peer disconnected and deregistered");
}

/// Send the directory's type=795 handshake response.
/// `dir_onion` is the bare onion address (without port); the location-string is
/// formatted as `<onion>:5222` to match the JoinMarket default port.
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
        location_string: format!("{}:5222", dir_onion),
        proto_ver_min: CURRENT_PROTO_VER,
        proto_ver_max: CURRENT_PROTO_VER,
        features: HashMap::new(),
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
                        from_nick = %from_nick,
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

                if let Some(msg) = parsed_msg {
                    dispatch_pubmsg(msg, body, nick.clone(), router, writer).await?;
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
                        from_nick = %from_nick,
                        "privmsg from_nick mismatch — disconnecting"
                    );
                    return Err(anyhow::anyhow!("privmsg from_nick spoofing attempt"));
                }
                dispatch_privmsg(&envelope.line, to_nick, nick.clone(), peer_onion, router).await?;
            }
        }

        msg_type::GETPEERLIST => {
            let response = router.get_peers_response();
            let mut entries: Vec<String> = Vec::with_capacity(response.peers.len() + 1);
            // Include DN itself (Python DN always includes itself in the peerlist)
            let dn_nick = router.dn_nick();
            let dn_loc = router.dn_location();
            if !dn_nick.is_empty() && !dn_loc.is_empty() {
                entries.push(format!("{};{}", dn_nick, dn_loc));
            }
            for maker in &response.peers {
                entries.push(format!("{};{}", maker.nick, maker.onion_address.as_location_string()));
            }
            let peerlist_body = entries.join(",");
            let env = OnionEnvelope::new(msg_type::PEERLIST, peerlist_body);
            send_envelope(writer, nick.as_ref(), &env).await?;
        }

        msg_type::PING => {
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

async fn dispatch_pubmsg(
    msg: JmMessage,
    body: &str,
    nick: Arc<str>,
    router: &Router,
    _writer: &mut BufWriter<BoxWriter>,
) -> anyhow::Result<()> {
    broadcast_pubmsg(&nick, body, router);
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
    if !router.send_to_peer(to_nick, fwd_bytes) {
        // Don't count messages directed at the DN's own nick as routing misses;
        // these are expected privmsg replies to heartbeat !orderbook probes.
        if to_nick != router.dn_nick() {
            metrics::counter!("jm_router_locate_misses_total").increment(1);
            tracing::debug!(
                from = %from_nick,
                target = %to_nick,
                "Target peer not found for privmsg relay"
            );
        }
        return Ok(());
    }
    metrics::counter!("jm_router_locate_hits_total").increment(1);

    // 2. Send a peerlist (type=789) with the sender's location to the target,
    //    so they can connect directly. Include the DN itself.
    if let Some(ref onion) = from_onion {
        let dn_nick = router.dn_nick();
        let dn_loc = router.dn_location();
        let mut entries = vec![
            format!("{};{}", from_nick, onion.as_location_string()),
        ];
        if !dn_nick.is_empty() && !dn_loc.is_empty() {
            entries.push(format!("{};{}", dn_nick, dn_loc));
        }
        let peerlist_env = OnionEnvelope::new(msg_type::PEERLIST, entries.join(","));
        let peerlist_bytes: Arc<str> = Arc::from(peerlist_env.serialize().as_str());
        router.send_to_peer(to_nick, peerlist_bytes);
    }
    Ok(())
}
