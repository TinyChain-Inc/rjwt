use super::*;
use crate::Actor;

#[test]
fn diagnostic_contract() {
    let marker = "synthetic_diagnostic_marker";
    let actor = Actor::new(marker.to_owned(), crate::AlgKind::Ed25519).unwrap();
    let signed = actor
        .sign_token(
            Token::new(
                (),
                UNIX_EPOCH,
                Duration::from_secs(60),
                marker.to_owned(),
                marker.to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
    let diagnostic = format!("{signed:?}");
    let contains_material = diagnostic.contains(signed.jwt()) || diagnostic.contains(marker);
    assert!(!contains_material);

    let error = token_signature(marker, AlgKind::Ed25519)
        .err()
        .expect("malformed structure must fail");
    assert!(matches!(error, Error::Format(_)));
    assert!(!error.message().contains(marker));

    let header = BASE64_STANDARD
        .encode(serde_json::to_vec(&TokenHeader::for_alg(AlgKind::Ed25519)).unwrap());
    for encoded in [marker.to_owned(), format!("{header}.{marker}")] {
        let error = decode_header_and_inherit(&encoded).expect_err("malformed structure must fail");
        assert!(matches!(error, Error::Format(_)));
        assert!(!error.message().contains(marker));
        let error = decode_token::<(), String, String>(&encoded)
            .err()
            .expect("malformed structure must fail");
        assert!(matches!(error, Error::Format(_)));
        assert!(!error.message().contains(marker));
    }
}
