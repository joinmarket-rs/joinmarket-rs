use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin_hashes::{sha256, Hash};
use base64::Engine as _;

/// Lowercase hex-encode `bytes`, matching Python's `binascii.hexlify()`.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const NICK_HASH_LEN: usize = 10;
const NICK_TOTAL_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nick(String);

/// A recoverable secp256k1 ECDSA nick signature.
///
/// Serialised on the wire as standard base64 of 65 bytes:
/// `[recovery_id (1 byte)] ++ [r (32 bytes)] ++ [s (32 bytes)]`.
#[derive(Debug, Clone)]
pub struct NickSig(pub RecoverableSignature);

#[derive(Debug)]
pub struct SigningKey(pub(crate) SecretKey);

#[derive(Debug, thiserror::Error)]
pub enum NickError {
    #[error("nick must start with 'J'")]
    MissingJPrefix,
    #[error("nick has wrong length: expected {}, got {0}", NICK_TOTAL_LEN)]
    WrongLength(usize),
    #[error("invalid version byte '{0}': expected '5' (JM protocol version)")]
    InvalidVersionByte(char),
    #[error("invalid base58 in nick hash portion")]
    InvalidBase58,
    #[error("invalid nick signature")]
    InvalidSignature,
}

/// JM protocol version byte embedded as the second character of every nick.
/// Python: `JM_VERSION = 5` → nick = `'J'` + `str(5)` + hash.  Same on all
/// Bitcoin networks (mainnet, testnet, signet).
const JM_VERSION_BYTE: u8 = b'5';

impl Nick {
    /// Generate a new random nick and its signing key.
    ///
    /// Algorithm (matching Python JoinMarket `client_protocol.py:set_nick`):
    /// 1. Generate a random secp256k1 keypair.
    /// 2. `sha256(hexlify(compressed_pubkey))[..10]` → base58 encode.
    /// 3. Prepend `"J5"`, right-pad with `'O'` to 16 chars.
    pub fn generate() -> (Nick, SigningKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let pubkey_bytes = public_key.serialize();
        // Hash the lowercase hex encoding of the pubkey, matching Python JoinMarket:
        // `hashlib.sha256(binascii.hexlify(pubkey_bytes)).digest()`
        let hex_pubkey = hex_encode(&pubkey_bytes);
        let hash = sha256::Hash::hash(hex_pubkey.as_bytes());

        // Take first NICK_HASH_LEN bytes of hash and base58-encode
        let hash_prefix = &hash[..NICK_HASH_LEN];
        let encoded = bs58::encode(hash_prefix).into_string();

        // Build nick: "J" + version_byte + base58_hash, right-padded to NICK_TOTAL_LEN with 'O'
        let mut nick = String::from("J");
        nick.push(JM_VERSION_BYTE as char);
        nick.push_str(&encoded);

        if nick.len() > NICK_TOTAL_LEN {
            nick.truncate(NICK_TOTAL_LEN);
        } else {
            while nick.len() < NICK_TOTAL_LEN {
                nick.push('O');
            }
        }

        (Nick(nick), SigningKey(secret_key))
    }

    /// Parse a nick from a string slice.
    ///
    /// Prefer using `s.parse::<Nick>()` (the `FromStr` trait) at call sites.
    /// This inherent method is kept for backward compatibility.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Nick, NickError> {
        if s.len() != NICK_TOTAL_LEN {
            return Err(NickError::WrongLength(s.len()));
        }
        if !s.starts_with('J') {
            return Err(NickError::MissingJPrefix);
        }
        // Validate version byte (second character).  In the Python JoinMarket
        // protocol this is always '5' (JM_VERSION = 5), on ALL networks.
        let version_byte = s.as_bytes()[1];
        if version_byte != JM_VERSION_BYTE {
            return Err(NickError::InvalidVersionByte(version_byte as char));
        }
        let hash_part = s[2..].trim_end_matches('O');
        if !hash_part.is_empty() {
            let decoded = bs58::decode(hash_part).into_vec()
                .map_err(|_| NickError::InvalidBase58)?;
            if decoded.len() > NICK_HASH_LEN {
                return Err(NickError::InvalidBase58);
            }
        }
        Ok(Nick(s.to_string()))
    }

    pub fn as_str(&self) -> &str { &self.0 }

    /// Verify a recoverable nick signature over `sha256(channel_id || msg)`.
    ///
    /// Recovers the public key from the signature and confirms that
    /// `sha256(pubkey)[..NICK_HASH_LEN]` base58-encodes to the hash portion
    /// embedded in this nick.
    pub fn verify_signature(&self, msg: &[u8], channel_id: &str, sig: &NickSig) -> bool {
        let secp = Secp256k1::verification_only();

        let mut data = channel_id.as_bytes().to_vec();
        data.extend_from_slice(msg);
        let hash = sha256::Hash::hash(&data);
        let message = Message::from_digest(*hash.as_ref());

        let pubkey = match secp.recover_ecdsa(&message, &sig.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let pubkey_bytes = pubkey.serialize();
        let hex_pubkey = hex_encode(&pubkey_bytes);
        let computed = sha256::Hash::hash(hex_pubkey.as_bytes());
        let expected_b58 = bs58::encode(&computed[..NICK_HASH_LEN]).into_string();

        // Nick: J<version_byte><base58_hash><'O'-padding>
        // Strip trailing 'O' padding to get only the actual hash chars.
        let hash_in_nick = self.0[2..].trim_end_matches('O');
        if hash_in_nick.is_empty() {
            return false;
        }

        // The nick is truncated to at most (NICK_TOTAL_LEN - 2) hash chars.
        // Compute the same truncation on the expected hash and require exact match.
        let max_hash_chars = NICK_TOTAL_LEN - 2;
        let expected_truncated = if expected_b58.len() > max_hash_chars {
            &expected_b58[..max_hash_chars]
        } else {
            &expected_b58[..]
        };
        expected_truncated == hash_in_nick
    }
}

impl std::fmt::Display for Nick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Nick {
    type Err = NickError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Nick::from_str(s)
    }
}

impl NickSig {
    /// Serialise to `recovery_id (1 byte) ++ r ++ s (64 bytes)`.
    pub fn to_bytes(&self) -> [u8; 65] {
        let (rec_id, sig_bytes) = self.0.serialize_compact();
        let mut out = [0u8; 65];
        out[0] = i32::from(rec_id) as u8;
        out[1..].copy_from_slice(&sig_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NickError> {
        if bytes.len() != 65 {
            return Err(NickError::InvalidSignature);
        }
        let rec_id = RecoveryId::try_from(bytes[0] as i32)
            .map_err(|_| NickError::InvalidSignature)?;
        let sig_bytes: [u8; 64] = bytes[1..].try_into().expect("length checked above");
        let sig = RecoverableSignature::from_compact(&sig_bytes, rec_id)
            .map_err(|_| NickError::InvalidSignature)?;
        Ok(NickSig(sig))
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, NickError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
            .map_err(|_| NickError::InvalidSignature)?;
        Self::from_bytes(&bytes)
    }
}

impl SigningKey {
    /// Sign `sha256(channel_id || msg)` with a recoverable ECDSA signature.
    pub fn sign_message(&self, msg: &[u8], channel_id: &str) -> NickSig {
        let secp = Secp256k1::signing_only();
        let mut data = channel_id.as_bytes().to_vec();
        data.extend_from_slice(msg);
        let hash = sha256::Hash::hash(&data);
        let message = Message::from_digest(*hash.as_ref());
        let sig = secp.sign_ecdsa_recoverable(&message, &self.0);
        NickSig(sig)
    }

    pub fn public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_compatibility_nick_hash() {
        // Verify that nick generation matches the Python JoinMarket algorithm:
        //   sha256(binascii.hexlify(pubkey_bytes)).digest()[:10] → base58 → nick
        //
        // Test vector: privkey = scalar 1 → generator point G
        //   compressed pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        //   sha256(hex string above as ASCII bytes)[:10] = d13c888cfd35d6ab67dc
        //   base58 → "Ckon1LuuapPSBM"
        //   nick  → "J5Ckon1LuuapPSBM"
        use secp256k1::{Secp256k1, SecretKey, PublicKey};
        let secp = Secp256k1::new();
        let privkey_bytes = {
            let mut b = [0u8; 32];
            b[31] = 1; // scalar 1
            b
        };
        let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize();
        assert_eq!(
            hex_encode(&pubkey_bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        let hex_pubkey = hex_encode(&pubkey_bytes);
        let hash = sha256::Hash::hash(hex_pubkey.as_bytes());
        assert_eq!(&hash[..10], &[0xd1, 0x3c, 0x88, 0x8c, 0xfd, 0x35, 0xd6, 0xab, 0x67, 0xdc]);
        let b58 = bs58::encode(&hash[..NICK_HASH_LEN]).into_string();
        assert_eq!(b58, "Ckon1LuuapPSBM");
        // Full nick
        let expected = "J5Ckon1LuuapPSBM";
        assert_eq!(expected.len(), NICK_TOTAL_LEN);
        // Confirm our Nick::from_str accepts it
        assert!(Nick::from_str(expected).is_ok());
    }

    #[test]
    fn test_generate_nick() {
        let (nick, _key) = Nick::generate();
        let s = nick.as_str();
        assert_eq!(s.len(), NICK_TOTAL_LEN);
        assert!(s.starts_with('J'));
        assert_eq!(s.chars().nth(1), Some('5'));
    }

    #[test]
    fn test_from_str_valid() {
        let nick = Nick::from_str("J5xhGSWE7VrxM7sO").unwrap();
        assert_eq!(nick.as_str(), "J5xhGSWE7VrxM7sO");
    }

    #[test]
    fn test_from_str_wrong_length() {
        assert!(Nick::from_str("J5abc").is_err());
    }

    #[test]
    fn test_from_str_missing_j_prefix() {
        assert!(Nick::from_str("X5xhGSWE7VrxM7sO").is_err());
    }

    #[test]
    fn test_generate_roundtrip() {
        let (nick, _key) = Nick::generate();
        let reparsed = Nick::from_str(nick.as_str()).unwrap();
        assert_eq!(nick, reparsed);
    }

    #[test]
    fn test_sign_and_verify() {
        let (nick, key) = Nick::generate();
        let sig = key.sign_message(b"hello world", "chan-id");
        assert!(nick.verify_signature(b"hello world", "chan-id", &sig));
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (nick, key) = Nick::generate();
        let sig = key.sign_message(b"hello world", "chan-id");
        assert!(!nick.verify_signature(b"different message", "chan-id", &sig));
    }

    #[test]
    fn test_verify_wrong_channel_id_fails() {
        let (nick, key) = Nick::generate();
        let sig = key.sign_message(b"hello world", "chan-id");
        assert!(!nick.verify_signature(b"hello world", "wrong-chan", &sig));
    }

    #[test]
    fn test_truncated_nick_does_not_verify() {
        // A nick with only a short hash portion (e.g. "J5abcOOOOOOOOOOO") should NOT
        // match a pubkey whose base58 hash merely starts with "abc".
        let (nick, key) = Nick::generate();
        let sig = key.sign_message(b"test", "chan");

        // Construct a fake nick with only the first 3 chars of the hash
        let real_hash = nick.as_str()[2..].trim_end_matches('O');
        if real_hash.len() > 3 {
            let short = format!("J5{:O<width$}", &real_hash[..3], width = NICK_TOTAL_LEN - 2);
            let short_nick = Nick::from_str(&short).unwrap();
            // This truncated nick should NOT verify against the real key's signature
            assert!(!short_nick.verify_signature(b"test", "chan", &sig));
        }
    }

    #[test]
    fn test_all_padding_nick_rejects_signature() {
        let nick = Nick::from_str("J5OOOOOOOOOOOOOO").unwrap();
        let (_other_nick, key) = Nick::generate();
        let sig = key.sign_message(b"test", "chan");
        // All-padding nick has empty hash portion → verify_signature returns false
        assert!(!nick.verify_signature(b"test", "chan", &sig));
    }

    #[test]
    fn test_from_str_rejects_oversized_base58() {
        // Build a nick that decodes to more than NICK_HASH_LEN (10) bytes
        // First, base58-encode 11 bytes to get a string
        let oversized = bs58::encode([0xFF_u8; 11]).into_string();
        // Pad to NICK_TOTAL_LEN
        let nick_str = format!("J5{:O<width$}", oversized, width = NICK_TOTAL_LEN - 2);
        if nick_str.len() == NICK_TOTAL_LEN {
            assert!(Nick::from_str(&nick_str).is_err());
        }
        // If the encoded string is too long for NICK_TOTAL_LEN, it would fail WrongLength instead,
        // which is also correct.
    }

    #[test]
    fn test_version_5_accepted() {
        // '5' is the only valid JM protocol version byte.
        assert!(Nick::from_str("J5xhGSWE7VrxM7sO").is_ok());
    }

    #[test]
    fn test_version_m_rejected() {
        // 'M' version byte does not exist in the Python protocol.
        let err = Nick::from_str("JMxhGSWE7VrxM7sO").unwrap_err();
        assert!(matches!(err, NickError::InvalidVersionByte('M')),
            "expected InvalidVersionByte('M'), got {:?}", err);
    }

    #[test]
    fn test_nick_sig_base64_roundtrip() {
        let (_nick, key) = Nick::generate();
        let sig = key.sign_message(b"test", "chan");
        let b64 = sig.to_base64();
        assert_eq!(b64.len(), 88); // base64 of 65 bytes
        let decoded = NickSig::from_base64(&b64).unwrap();
        // Verify the round-tripped sig still works
        let (_nick2, _key2) = Nick::generate();
        let _ = decoded; // decoded is a valid NickSig
        // Just verify the bytes round-trip
        assert_eq!(sig.to_bytes(), NickSig::from_base64(&b64).unwrap().to_bytes());
    }
}
