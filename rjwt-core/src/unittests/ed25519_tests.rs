use std::time::{Duration, SystemTime};

use crate::token::{decode_token, token_signature};

use crate::*;

const SIZE_LIMIT: usize = 8000; // max HTTP header size

#[test]
fn test_format() {
    let actor = Actor::new("actor".to_string());
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );

    let signed = actor.sign_token(token).unwrap();
    let (message, _) = token_signature(signed.jwt(), AlgKind::Ed25519).unwrap();

    assert!(signed.jwt().starts_with(message));
    assert!(signed.jwt().len() < SIZE_LIMIT);
}

#[test]
fn test_decode_alg_eddsa() {
    let actor = Actor::new("actor".to_string());
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let result = decode_token::<String, String, ()>(signed.jwt());
    match result {
        Ok((AlgKind::Ed25519, _)) => {}
        other => panic!("expected Ok((AlgKind::Ed25519, _)), got {:?}", other),
    }
}

#[test]
fn test_decode_unknown_alg() {
    use base64::prelude::*;
    let header = BASE64_STANDARD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
    let jwt = format!("{}.dummy_body.dummy_sig", header);
    let result = decode_token::<String, String, ()>(&jwt);
    assert!(
        matches!(result, Err(Error::Format(_))),
        "expected Err(Error::Format), got {:?}",
        result
    );
}

#[test]
fn test_decode_missing_alg() {
    use base64::prelude::*;
    let header = BASE64_STANDARD.encode(b"{\"typ\":\"JWT\"}");
    let jwt = format!("{}.dummy_body.dummy_sig", header);
    let result = decode_token::<String, String, ()>(&jwt);
    assert!(
        matches!(result, Err(Error::Format(_)) | Err(Error::Json(_))),
        "expected Err(Error::Format) or Err(Error::Json), got {:?}",
        result
    );
}

#[test]
fn test_decode_malformed_header_json() {
    use base64::prelude::*;
    let header = BASE64_STANDARD.encode(b"not json");
    let jwt = format!("{}.dummy_body.dummy_sig", header);
    let result = decode_token::<String, String, ()>(&jwt);
    assert!(
        matches!(result, Err(Error::Format(_)) | Err(Error::Json(_))),
        "expected Err(Error::Format) or Err(Error::Json), got {:?}",
        result
    );
}

#[test]
fn test_sig_signing_key_generate_ed25519() {
    let sk = SigningKey::generate_ed25519();
    let sig = sk.sign(b"hello").unwrap();
    let vk = sk.verifying_key();
    assert!(vk.verify(b"hello", &sig).is_ok());
}

#[test]
fn test_sig_verifying_key_ed25519_roundtrip() {
    let sk = SigningKey::generate_ed25519();
    let vk = sk.verifying_key();
    let bytes = vk.to_bytes();
    let vk2 = VerifyingKey::from_bytes(AlgKind::Ed25519, &bytes).unwrap();
    let sig = sk.sign(b"roundtrip").unwrap();
    assert!(vk2.verify(b"roundtrip", &sig).is_ok());
}

#[test]
fn test_sig_signature_from_bytes_ed25519() {
    let sk = SigningKey::generate_ed25519();
    let sig = sk.sign(b"test message").unwrap();
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(AlgKind::Ed25519, &bytes).unwrap();
    let vk = sk.verifying_key();
    assert!(vk.verify(b"test message", &sig2).is_ok());
}
