use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Sentinel location-string used by peers that do not serve an onion hidden service.
/// Python JoinMarket clients use this value instead of an empty string.
pub const NOT_SERVING_ONION: &str = "NOT-SERVING-ONION";

// ── Onion channel wire protocol ───────────────────────────────────────────────

/// Integer type discriminators used in the onion channel JSON envelope.
pub mod msg_type {
    pub const PRIVMSG:      u32 = 685;
    pub const PUBMSG:       u32 = 687;
    pub const PEERLIST:     u32 = 789;
    pub const GETPEERLIST:  u32 = 791;
    pub const HANDSHAKE:    u32 = 793;
    pub const DN_HANDSHAKE: u32 = 795;
    pub const PING:         u32 = 797;
    pub const PONG:         u32 = 799;
    pub const DISCONNECT:   u32 = 801;
}

/// Every message on the wire is wrapped in this JSON envelope, terminated by `\r\n`.
/// `"type"` is an integer discriminator; `"line"` carries the payload string.
#[derive(Debug, Serialize, Deserialize)]
pub struct OnionEnvelope {
    #[serde(rename = "type")]
    pub msg_type: u32,
    pub line: String,
}

impl OnionEnvelope {
    pub fn new(msg_type: u32, line: impl Into<String>) -> Self {
        OnionEnvelope { msg_type, line: line.into() }
    }

    /// Serialize to JSON and append `\r\n` (the wire delimiter).
    pub fn serialize(&self) -> String {
        let mut s = serde_json::to_string(self).expect("infallible");
        s.push_str("\r\n");
        s
    }

    /// Parse from a line (leading/trailing whitespace and line-endings stripped).
    pub fn parse(s: &str) -> Result<Self, serde_json::Error> {
        let s = s.trim_end_matches('\n').trim_end_matches('\r');
        serde_json::from_str(s)
    }
}

/// Parse a pubmsg line `"<from_nick>!PUBLIC<body>"` into `(from_nick, body)`.
pub fn parse_pubmsg_line(line: &str) -> Option<(&str, &str)> {
    let bang_pos = line.find('!')?;
    let from_nick = &line[..bang_pos];
    let rest = &line[bang_pos + 1..];
    let body = rest.strip_prefix("PUBLIC")?;
    Some((from_nick, body))
}

/// Parse a privmsg line `"<from_nick>!<to_nick>!<body>"` into `(from_nick, to_nick, body)`.
pub fn parse_privmsg_line(line: &str) -> Option<(&str, &str, &str)> {
    let first_bang = line.find('!')?;
    let from_nick = &line[..first_bang];
    let rest = &line[first_bang + 1..];
    let second_bang = rest.find('!')?;
    let to_nick = &rest[..second_bang];
    let body = &rest[second_bang + 1..];
    Some((from_nick, to_nick, body))
}

/// Build a pubmsg line `"<nick>!PUBLIC<body>"`.
pub fn make_pubmsg_line(from_nick: &str, body: &str) -> String {
    format!("{}!PUBLIC{}", from_nick, body)
}

// ── JoinMarket message types ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageCommand {
    Ann,
    Orderbook,
    Fill,
    AbsOrder,
    RelOrder,
    IoAuth,
    TxSigs,
    PushTx,
    Disconnect,
    Getpeers,
    Peers,
    Ping,
    Pong,
}

#[derive(Debug, Clone)]
pub struct NickSig(pub String);

#[derive(Debug, Clone)]
pub struct JmMessage {
    pub command: MessageCommand,
    pub fields: Vec<String>,
    pub nick_sig: Option<NickSig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("message must start with '!'")]
    MissingBang,
    #[error("empty command")]
    EmptyCommand,
    #[error("unknown command: {0}")]
    UnknownCommand(String),
}

impl MessageCommand {
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "ann"        => Ok(MessageCommand::Ann),
            "orderbook"  => Ok(MessageCommand::Orderbook),
            "fill"       => Ok(MessageCommand::Fill),
            "absorder"   => Ok(MessageCommand::AbsOrder),
            "relorder"   => Ok(MessageCommand::RelOrder),
            "ioauth"     => Ok(MessageCommand::IoAuth),
            "txsigs"     => Ok(MessageCommand::TxSigs),
            "pushtx"     => Ok(MessageCommand::PushTx),
            "disconnect" => Ok(MessageCommand::Disconnect),
            "getpeers"   => Ok(MessageCommand::Getpeers),
            "peers"      => Ok(MessageCommand::Peers),
            "ping"       => Ok(MessageCommand::Ping),
            "pong"       => Ok(MessageCommand::Pong),
            other        => Err(ParseError::UnknownCommand(other.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MessageCommand::Ann        => "ann",
            MessageCommand::Orderbook  => "orderbook",
            MessageCommand::Fill       => "fill",
            MessageCommand::AbsOrder   => "absorder",
            MessageCommand::RelOrder   => "relorder",
            MessageCommand::IoAuth     => "ioauth",
            MessageCommand::TxSigs     => "txsigs",
            MessageCommand::PushTx     => "pushtx",
            MessageCommand::Disconnect => "disconnect",
            MessageCommand::Getpeers   => "getpeers",
            MessageCommand::Peers      => "peers",
            MessageCommand::Ping       => "ping",
            MessageCommand::Pong       => "pong",
        }
    }
}

impl JmMessage {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let raw = raw.trim_end_matches('\n').trim_end_matches('\r');

        if !raw.starts_with('!') {
            return Err(ParseError::MissingBang);
        }

        let content = &raw[1..];
        if content.is_empty() {
            return Err(ParseError::EmptyCommand);
        }

        let parts: Vec<&str> = content.splitn(2, ' ').collect();
        let cmd_str = parts[0].to_lowercase();
        let command = MessageCommand::from_str(&cmd_str)?;

        let fields: Vec<String> = if parts.len() > 1 {
            parts[1].split_whitespace().map(|s| s.to_string()).collect()
        } else {
            vec![]
        };

        // Check for trailing nick signature (last field starting with specific pattern)
        // In JoinMarket, nick sigs are typically the last field
        let (fields, nick_sig) = extract_nick_sig(fields);

        Ok(JmMessage { command, fields, nick_sig })
    }

    pub fn serialize(&self) -> String {
        let mut result = format!("!{}", self.command.as_str());
        for field in &self.fields {
            result.push(' ');
            result.push_str(field);
        }
        if let Some(sig) = &self.nick_sig {
            result.push(' ');
            result.push_str(&sig.0);
        }
        result.push('\n');
        result
    }
}

/// Heuristic: if the last field is base64-encoded 65 bytes (88 or 87 chars),
/// treat it as a nick signature.  This can misidentify a regular field that
/// happens to be 88 chars of valid base64 decoding to 65 bytes, but in
/// practice JoinMarket message fields never collide with this pattern.
fn extract_nick_sig(mut fields: Vec<String>) -> (Vec<String>, Option<NickSig>) {
    if let Some(last) = fields.last() {
        let len = last.len();
        if len == 88 || len == 87 {
            // Try to confirm it decodes to 65 bytes
            let decoded = base64::engine::general_purpose::STANDARD.decode(last)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(last));
            if let Ok(bytes) = decoded {
                if bytes.len() == 65 {
                    let sig_str = fields.pop().unwrap();
                    return (fields, Some(NickSig(sig_str)));
                }
            }
        }
    }
    (fields, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_getpeers() {
        let msg = JmMessage::parse("!getpeers\n").unwrap();
        assert_eq!(msg.command, MessageCommand::Getpeers);
        assert!(msg.fields.is_empty());
    }

    #[test]
    fn test_parse_ping() {
        let msg = JmMessage::parse("!ping").unwrap();
        assert_eq!(msg.command, MessageCommand::Ping);
    }

    #[test]
    fn test_parse_fill() {
        let msg = JmMessage::parse("!fill J5targetNick 1000000 abc").unwrap();
        assert_eq!(msg.command, MessageCommand::Fill);
        assert_eq!(msg.fields[0], "J5targetNick");
        assert_eq!(msg.fields[1], "1000000");
    }

    #[test]
    fn test_missing_bang() {
        assert!(JmMessage::parse("getpeers").is_err());
    }

    #[test]
    fn test_unknown_command() {
        assert!(JmMessage::parse("!foobar").is_err());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let msg = JmMessage {
            command: MessageCommand::Getpeers,
            fields: vec![],
            nick_sig: None,
        };
        let serialized = msg.serialize();
        assert_eq!(serialized, "!getpeers\n");
    }

    #[test]
    fn test_serialize_with_fields() {
        let msg = JmMessage {
            command: MessageCommand::Fill,
            fields: vec!["J5nick".to_string(), "1000000".to_string()],
            nick_sig: None,
        };
        let serialized = msg.serialize();
        assert_eq!(serialized, "!fill J5nick 1000000\n");
    }

    #[test]
    fn test_command_case_insensitive() {
        // Commands should be parsed case-insensitively
        assert_eq!(JmMessage::parse("!PING").unwrap().command, MessageCommand::Ping);
        assert_eq!(JmMessage::parse("!Ping").unwrap().command, MessageCommand::Ping);
        assert_eq!(JmMessage::parse("!GETPEERS").unwrap().command, MessageCommand::Getpeers);
    }

    #[test]
    fn test_message_with_many_fields() {
        let msg = JmMessage::parse("!fill a b c d e f").unwrap();
        assert_eq!(msg.command, MessageCommand::Fill);
        assert_eq!(msg.fields.len(), 6);
        assert_eq!(msg.fields[5], "f");
    }

    #[test]
    fn test_onion_envelope_roundtrip() {
        let env = OnionEnvelope::new(msg_type::PING, "");
        let serialized = env.serialize();
        assert!(serialized.ends_with("\r\n"));
        let parsed = OnionEnvelope::parse(serialized.trim_end()).unwrap();
        assert_eq!(parsed.msg_type, msg_type::PING);
        assert_eq!(parsed.line, "");
    }

    #[test]
    fn test_parse_pubmsg_line() {
        let (nick, body) = parse_pubmsg_line("J5maker!PUBLIC!ann hello").unwrap();
        assert_eq!(nick, "J5maker");
        assert_eq!(body, "!ann hello");
    }

    #[test]
    fn test_parse_privmsg_line() {
        // Wire format: "<from>!<to>!<body>"; body is a JM command so includes its own '!'
        // giving a double-'!': "J5taker!J5maker!!fill 1000000"
        let (from, to, body) = parse_privmsg_line("J5taker!J5maker!!fill 1000000").unwrap();
        assert_eq!(from, "J5taker");
        assert_eq!(to, "J5maker");
        assert_eq!(body, "!fill 1000000");
    }

    #[test]
    fn test_make_pubmsg_line() {
        let line = make_pubmsg_line("J5dir", "!peerinfo J5maker xxx.onion:5222");
        assert_eq!(line, "J5dir!PUBLIC!peerinfo J5maker xxx.onion:5222");
    }
}
