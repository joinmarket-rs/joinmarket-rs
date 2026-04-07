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
    // Public broadcast — offer types
    AbsOffer,
    RelOffer,
    SwAbsOffer,
    SwRelOffer,
    Sw0AbsOffer,
    Sw0RelOffer,
    // Public broadcast — other
    Orderbook,
    Cancel,
    Hp2,
    TBond,
    // Private commands
    Fill,
    IoAuth,
    Auth,
    PubKey,
    Tx,
    Sig,
    Push,
    Error,
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
            "absoffer"    => Ok(MessageCommand::AbsOffer),
            "reloffer"    => Ok(MessageCommand::RelOffer),
            "swabsoffer"  => Ok(MessageCommand::SwAbsOffer),
            "swreloffer"  => Ok(MessageCommand::SwRelOffer),
            "sw0absoffer" => Ok(MessageCommand::Sw0AbsOffer),
            "sw0reloffer" => Ok(MessageCommand::Sw0RelOffer),
            "orderbook"   => Ok(MessageCommand::Orderbook),
            "cancel"      => Ok(MessageCommand::Cancel),
            "hp2"         => Ok(MessageCommand::Hp2),
            "tbond"       => Ok(MessageCommand::TBond),
            "fill"        => Ok(MessageCommand::Fill),
            "ioauth"      => Ok(MessageCommand::IoAuth),
            "auth"        => Ok(MessageCommand::Auth),
            "pubkey"      => Ok(MessageCommand::PubKey),
            "tx"          => Ok(MessageCommand::Tx),
            "sig"         => Ok(MessageCommand::Sig),
            "push"        => Ok(MessageCommand::Push),
            "error"       => Ok(MessageCommand::Error),
            other         => Err(ParseError::UnknownCommand(other.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MessageCommand::AbsOffer    => "absoffer",
            MessageCommand::RelOffer    => "reloffer",
            MessageCommand::SwAbsOffer  => "swabsoffer",
            MessageCommand::SwRelOffer  => "swreloffer",
            MessageCommand::Sw0AbsOffer => "sw0absoffer",
            MessageCommand::Sw0RelOffer => "sw0reloffer",
            MessageCommand::Orderbook   => "orderbook",
            MessageCommand::Cancel      => "cancel",
            MessageCommand::Hp2         => "hp2",
            MessageCommand::TBond       => "tbond",
            MessageCommand::Fill        => "fill",
            MessageCommand::IoAuth      => "ioauth",
            MessageCommand::Auth        => "auth",
            MessageCommand::PubKey      => "pubkey",
            MessageCommand::Tx          => "tx",
            MessageCommand::Sig         => "sig",
            MessageCommand::Push        => "push",
            MessageCommand::Error       => "error",
        }
    }

    /// Returns `true` if this command is an offer type (maker announcement).
    pub fn is_offer(&self) -> bool {
        matches!(self,
            MessageCommand::AbsOffer |
            MessageCommand::RelOffer |
            MessageCommand::SwAbsOffer |
            MessageCommand::SwRelOffer |
            MessageCommand::Sw0AbsOffer |
            MessageCommand::Sw0RelOffer
        )
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
    fn test_envelope_only_commands_rejected() {
        // These are envelope-level types (791, 797, 799, 801), not ! commands
        assert!(JmMessage::parse("!getpeers").is_err());
        assert!(JmMessage::parse("!ping").is_err());
        assert!(JmMessage::parse("!pong").is_err());
        assert!(JmMessage::parse("!disconnect").is_err());
        assert!(JmMessage::parse("!peers").is_err());
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
            command: MessageCommand::Orderbook,
            fields: vec![],
            nick_sig: None,
        };
        let serialized = msg.serialize();
        assert_eq!(serialized, "!orderbook\n");
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
        assert_eq!(JmMessage::parse("!FILL").unwrap().command, MessageCommand::Fill);
        assert_eq!(JmMessage::parse("!Fill").unwrap().command, MessageCommand::Fill);
        assert_eq!(JmMessage::parse("!SW0ABSOFFER").unwrap().command, MessageCommand::Sw0AbsOffer);
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
        let (nick, body) = parse_pubmsg_line("J5maker!PUBLIC!sw0absoffer minsize=27300").unwrap();
        assert_eq!(nick, "J5maker");
        assert_eq!(body, "!sw0absoffer minsize=27300");
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

    #[test]
    fn test_parse_python_commands() {
        // Offer types (public broadcast)
        let offer_cmds = [
            ("!absoffer", MessageCommand::AbsOffer),
            ("!reloffer", MessageCommand::RelOffer),
            ("!swabsoffer", MessageCommand::SwAbsOffer),
            ("!swreloffer", MessageCommand::SwRelOffer),
            ("!sw0absoffer", MessageCommand::Sw0AbsOffer),
            ("!sw0reloffer", MessageCommand::Sw0RelOffer),
        ];
        for (raw, expected) in &offer_cmds {
            let msg = JmMessage::parse(raw).unwrap();
            assert_eq!(msg.command, *expected, "failed to parse {}", raw);
            assert!(msg.command.is_offer(), "{} should be an offer", raw);
        }

        // Other public commands
        assert_eq!(JmMessage::parse("!cancel 0").unwrap().command, MessageCommand::Cancel);
        assert_eq!(JmMessage::parse("!hp2 abc").unwrap().command, MessageCommand::Hp2);
        assert_eq!(JmMessage::parse("!tbond proof").unwrap().command, MessageCommand::TBond);

        // Private commands
        assert_eq!(JmMessage::parse("!auth data").unwrap().command, MessageCommand::Auth);
        assert_eq!(JmMessage::parse("!pubkey abc").unwrap().command, MessageCommand::PubKey);
        assert_eq!(JmMessage::parse("!tx data").unwrap().command, MessageCommand::Tx);
        assert_eq!(JmMessage::parse("!sig data").unwrap().command, MessageCommand::Sig);
        assert_eq!(JmMessage::parse("!push data").unwrap().command, MessageCommand::Push);
        assert_eq!(JmMessage::parse("!error msg").unwrap().command, MessageCommand::Error);
    }

    #[test]
    fn test_is_offer() {
        assert!(!MessageCommand::Orderbook.is_offer());
        assert!(!MessageCommand::Cancel.is_offer());
        assert!(!MessageCommand::Fill.is_offer());
        assert!(MessageCommand::Sw0AbsOffer.is_offer());
    }
}
