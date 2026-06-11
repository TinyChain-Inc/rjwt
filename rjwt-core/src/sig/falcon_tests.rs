use std::time::{Duration, SystemTime};

use super::falcon::{
    Falcon512Backend, Falcon512KeyPair, Falcon512PrivateKey, Falcon512PublicKey,
    Falcon512Signature, FalconBackend, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use super::*;
use crate::*;

#[test]
fn test_falcon_public_key_from_bytes_wrong_length() {
    let result = Falcon512PublicKey::from_bytes(&[0u8; 100]);
    assert!(matches!(result, Err(Error::Format(_))));
    let result = Falcon512PublicKey::from_bytes(&[0u8; 1000]);
    assert!(matches!(result, Err(Error::Format(_))));
    let result = Falcon512PublicKey::from_bytes(&[0u8; PUBLIC_KEY_LEN]);
    assert!(result.is_ok());
}

#[test]
fn test_falcon_signature_from_bytes_wrong_length() {
    let result = Falcon512Signature::from_bytes(&[0u8; SIGNATURE_LEN]);
    assert!(result.is_ok());
    let result = Falcon512Signature::from_bytes(&[0u8; 665]);
    assert!(matches!(result, Err(Error::Format(_))));
    let result = Falcon512Signature::from_bytes(&[0u8; 667]);
    assert!(matches!(result, Err(Error::Format(_))));
}

#[test]
fn test_falcon_public_key_byte_roundtrip() {
    let some_897_bytes = [42u8; PUBLIC_KEY_LEN];
    let pk = Falcon512PublicKey::from_bytes(&some_897_bytes).unwrap();
    assert_eq!(pk.as_bytes(), &some_897_bytes[..]);
}

#[test]
fn test_sig_signature_from_bytes_falcon() {
    let result = Signature::from_bytes(AlgKind::Falcon512, &[0u8; SIGNATURE_LEN]);
    let sig = result.unwrap();
    assert_eq!(sig.alg(), AlgKind::Falcon512);
    let result = Signature::from_bytes(AlgKind::Falcon512, &[0u8; 100]);
    assert!(matches!(result, Err(Error::Format(_))));
}

#[test]
fn test_alg_kind_jwt_name_roundtrip() {
    for alg in [AlgKind::Ed25519, AlgKind::Falcon512] {
        assert_eq!(AlgKind::from_jwt_name(alg.jwt_name()).unwrap(), alg);
    }
}

struct TestResolver {
    hostname: String,
    actors: std::collections::HashMap<(String, String), Actor<String>>,
}

impl TestResolver {
    fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            actors: std::collections::HashMap::new(),
        }
    }

    fn add(&mut self, actor: Actor<String>) {
        self.actors
            .insert((self.hostname.clone(), actor.id().clone()), actor);
    }
}

impl Resolve for TestResolver {
    type HostId = String;
    type ActorId = String;
    type Claims = ();

    fn resolve(
        &self,
        host: &Self::HostId,
        actor_id: &Self::ActorId,
    ) -> impl std::future::Future<Output = Result<Actor<Self::ActorId>, Error>> + Send {
        let result = self
            .actors
            .get(&(host.clone(), actor_id.clone()))
            .cloned()
            .ok_or_else(|| Error::fetch(format!("{}:{}", host, actor_id)));
        async move { result }
    }
}

fn falcon_actor(id: &str) -> Actor<String> {
    Actor::<String>::new_falcon512(id.to_string()).expect("falcon actor")
}

#[test]
fn test_falcon_new_falcon512_default_constructor() {
    let id = "test-actor".to_string();
    let actor = Actor::<String>::new_falcon512(id);
    assert!(actor.is_ok());
    let actor = actor.unwrap();
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let (alg, _) = token::decode_token::<String, String, ()>(signed.jwt()).unwrap();
    assert_eq!(alg, AlgKind::Falcon512);
}

#[test]
fn test_falcon_sign_verify_roundtrip() {
    let actor = falcon_actor("alice");
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let (alg, _) = token::decode_token::<String, String, ()>(signed.jwt()).unwrap();
    assert_eq!(alg, AlgKind::Falcon512);
    let (message, signature) = token::token_signature(signed.jwt(), AlgKind::Falcon512).unwrap();
    assert!(
        actor
            .verifying_key()
            .verify(message.as_bytes(), &signature)
            .is_ok()
    );
}

#[test]
fn test_falcon_depth1_under_8kb() {
    let actor = falcon_actor("alice");
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    assert!(
        signed.jwt().len() < 8000,
        "JWT too large: {} bytes",
        signed.jwt().len()
    );
}

#[test]
fn test_falcon_depth2_chain_under_8kb() {
    let root = falcon_actor("root");
    let delegate = falcon_actor("delegate");
    let now = SystemTime::now();
    let token = Token::new(
        "example.com".to_string(),
        now,
        Duration::from_secs(30),
        root.id().to_string(),
        "root claim".to_string(),
    );
    let signed_root = root.sign_token(token).unwrap();
    let signed_child = delegate
        .consume_and_sign(
            signed_root,
            "relay.com".to_string(),
            "delegate claim".to_string(),
            now,
        )
        .unwrap();
    assert!(
        signed_child.jwt().len() < 8000,
        "chained JWT too large: {} bytes",
        signed_child.jwt().len()
    );
}

#[test]
fn test_falcon_signing_is_randomized() {
    let actor = falcon_actor("alice");
    let now = SystemTime::now();
    let token1 = Token::new(
        "example.com".to_string(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let token2 = Token::new(
        "example.com".to_string(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed1 = actor.sign_token(token1).unwrap();
    let signed2 = actor.sign_token(token2).unwrap();
    let sig1 = signed1.jwt().rsplit('.').next().unwrap();
    let sig2 = signed2.jwt().rsplit('.').next().unwrap();
    assert_ne!(sig1, sig2, "Falcon signatures must be randomized");
    let (msg1, s1) = token::token_signature(signed1.jwt(), AlgKind::Falcon512).unwrap();
    let (msg2, s2) = token::token_signature(signed2.jwt(), AlgKind::Falcon512).unwrap();
    assert!(actor.verifying_key().verify(msg1.as_bytes(), &s1).is_ok());
    assert!(actor.verifying_key().verify(msg2.as_bytes(), &s2).is_ok());
}

#[test]
fn test_falcon_actor_clone_drops_private_key() {
    let actor = falcon_actor("alice");
    assert!(actor.has_private_key());
    let cloned = actor.clone();
    assert!(!cloned.has_private_key());
    let token = Token::new(
        "example.com".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let (message, signature) = token::token_signature(signed.jwt(), AlgKind::Falcon512).unwrap();
    assert!(
        cloned
            .verifying_key()
            .verify(message.as_bytes(), &signature)
            .is_ok()
    );
}

#[test]
fn test_falcon_signature_is_exactly_666_bytes() {
    let actor = Actor::<String>::new_falcon512("a".to_string()).unwrap();
    let token = Token::new(
        "h".to_string(),
        SystemTime::now(),
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let (_, signature) = token::token_signature(signed.jwt(), AlgKind::Falcon512).unwrap();
    assert_eq!(signature.to_bytes().len(), 666);
}

#[test]
fn test_decode_alg_fndsa512_dispatches_to_falcon() {
    use futures::executor::block_on;

    let host = "example.com".to_string();
    let actor = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();

    let (alg, _) = token::decode_token::<String, String, ()>(signed.jwt()).unwrap();
    assert_eq!(alg, AlgKind::Falcon512);

    let mut resolver = TestResolver::new(host.clone());
    resolver.add(actor.clone());

    let result = block_on(resolver.verify(signed.jwt().to_string(), now));
    let verified = result.expect("Resolve::verify should succeed for a valid Falcon-512 token");
    assert_eq!(
        verified.claims().get(&host, &"alice".to_string()),
        Some(&()),
    );
}

#[test]
fn test_chain_alg_mismatch_outer_eddsa_inner_falcon_rejected() {
    use futures::executor::block_on;

    let now = SystemTime::now();
    let inner_actor = falcon_actor("inner");
    let outer_actor = Actor::<String>::new("outer".to_string());

    let inner_token = Token::new(
        "inner.com".to_string(),
        now,
        Duration::from_secs(30),
        inner_actor.id().to_string(),
        (),
    );
    let signed_inner = inner_actor.sign_token(inner_token).unwrap();

    let mut inner_resolver = TestResolver::new("inner.com");
    inner_resolver.add(inner_actor.clone());
    let verified_inner =
        block_on(inner_resolver.verify(signed_inner.jwt().to_string(), now)).unwrap();

    let signed_outer = outer_actor
        .consume_and_sign(verified_inner, "outer.com".to_string(), (), now)
        .unwrap();

    let mut resolver = TestResolver::new("outer.com");
    resolver.add(outer_actor.clone());

    let result = block_on(resolver.verify(signed_outer.jwt().to_string(), now));
    match &result {
        Err(Error::Auth(msg)) => {
            assert!(
                msg.contains("mixed") || msg.contains("algorithm"),
                "expected message mentioning 'mixed' or 'algorithm', got: {msg}"
            );
        }
        other => panic!("expected Err(Error::Auth(_)), got {:?}", other),
    }
}

#[test]
fn test_chain_alg_mismatch_outer_falcon_inner_eddsa_rejected() {
    use futures::executor::block_on;

    let now = SystemTime::now();
    let inner_actor = Actor::<String>::new("inner".to_string());
    let outer_actor = falcon_actor("outer");

    let inner_token = Token::new(
        "inner.com".to_string(),
        now,
        Duration::from_secs(30),
        inner_actor.id().to_string(),
        (),
    );
    let signed_inner = inner_actor.sign_token(inner_token).unwrap();

    let mut inner_resolver = TestResolver::new("inner.com");
    inner_resolver.add(inner_actor.clone());
    let verified_inner =
        block_on(inner_resolver.verify(signed_inner.jwt().to_string(), now)).unwrap();

    let signed_outer = outer_actor
        .consume_and_sign(verified_inner, "outer.com".to_string(), (), now)
        .unwrap();

    let mut resolver = TestResolver::new("outer.com");
    resolver.add(outer_actor.clone());

    let result = block_on(resolver.verify(signed_outer.jwt().to_string(), now));
    match &result {
        Err(Error::Auth(msg)) => {
            assert!(
                msg.contains("mixed") || msg.contains("algorithm"),
                "expected message mentioning 'mixed' or 'algorithm', got: {msg}"
            );
        }
        other => panic!("expected Err(Error::Auth(_)), got {:?}", other),
    }
}

#[test]
fn test_pre_pass_fails_before_resolver_invoked() {
    use futures::executor::block_on;

    struct PanicOnResolve;

    impl Resolve for PanicOnResolve {
        type HostId = String;
        type ActorId = String;
        type Claims = ();

        fn resolve(
            &self,
            _host: &Self::HostId,
            _actor_id: &Self::ActorId,
        ) -> impl std::future::Future<Output = Result<Actor<Self::ActorId>, Error>> + Send {
            async { panic!("resolver must not be called for mixed-alg chains") }
        }
    }

    let now = SystemTime::now();
    let inner_actor = falcon_actor("inner");
    let outer_actor = Actor::<String>::new("outer".to_string());

    let inner_token = Token::new(
        "inner.com".to_string(),
        now,
        Duration::from_secs(30),
        inner_actor.id().to_string(),
        (),
    );
    let signed_inner = inner_actor.sign_token(inner_token).unwrap();

    let mut inner_resolver = TestResolver::new("inner.com");
    inner_resolver.add(inner_actor.clone());
    let verified_inner =
        block_on(inner_resolver.verify(signed_inner.jwt().to_string(), now)).unwrap();

    let signed_outer = outer_actor
        .consume_and_sign(verified_inner, "outer.com".to_string(), (), now)
        .unwrap();

    let result = block_on(PanicOnResolve.verify(signed_outer.jwt().to_string(), now));
    match &result {
        Err(Error::Auth(msg)) => {
            assert!(
                msg.contains("mixed") || msg.contains("algorithm"),
                "expected message mentioning 'mixed' or 'algorithm', got: {msg}"
            );
        }
        other => panic!("expected Err(Error::Auth(_)), got {:?}", other),
    }
}

#[test]
fn test_falcon_tampered_signature_rejected() {
    use base64::prelude::*;
    use futures::executor::block_on;

    let host = "h".to_string();
    let actor = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let jwt = signed.jwt();

    let i = jwt.rfind('.').unwrap();
    let mut sig_bytes = BASE64_STANDARD.decode(&jwt[(i + 1)..]).unwrap();
    let last = sig_bytes.len() - 1;
    sig_bytes[last] ^= 0x01;
    let tampered_sig = BASE64_STANDARD.encode(&sig_bytes);
    let tampered = format!("{}.{}", &jwt[..i], tampered_sig);

    let mut resolver = TestResolver::new(host.clone());
    resolver.add(actor.clone());

    let result = block_on(resolver.verify(tampered, now));
    assert!(
        matches!(result, Err(Error::Auth(_))),
        "expected Err(Error::Auth(_)), got {:?}",
        result
    );
}

#[test]
fn test_falcon_tampered_message_rejected() {
    use base64::prelude::*;
    use futures::executor::block_on;

    let host = "h".to_string();
    let actor = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();
    let jwt = signed.jwt();

    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    let header = parts[0];
    let body_and_sig = parts[2];
    let mut body_bytes = BASE64_STANDARD.decode(parts[1]).unwrap();
    let mid = body_bytes.len() / 2;
    body_bytes[mid] ^= 0x01;
    let tampered_body = BASE64_STANDARD.encode(&body_bytes);
    let tampered = format!("{}.{}.{}", header, tampered_body, body_and_sig);

    let mut resolver = TestResolver::new(host.clone());
    resolver.add(actor.clone());

    let result = block_on(resolver.verify(tampered, now));
    assert!(
        matches!(
            result,
            Err(Error::Auth(_))
                | Err(Error::Base64(_))
                | Err(Error::Format(_))
                | Err(Error::Json(_))
        ),
        "expected token rejection error, got {:?}",
        result
    );
}

#[test]
fn test_falcon_expired_token_rejected() {
    use futures::executor::block_on;

    let host = "h".to_string();
    let actor = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        actor.id().to_string(),
        (),
    );
    let signed = actor.sign_token(token).unwrap();

    let mut resolver = TestResolver::new(host.clone());
    resolver.add(actor.clone());

    let later = now + Duration::from_secs(60);
    let result = block_on(resolver.verify(signed.jwt().to_string(), later));
    assert!(
        matches!(result, Err(Error::Time(_))),
        "expected Err(Error::Time(_)), got {:?}",
        result
    );
}

#[test]
fn test_falcon_actor_id_mismatch_rejected() {
    use futures::executor::block_on;

    struct MismatchedResolver {
        actor: Actor<String>,
    }

    impl Resolve for MismatchedResolver {
        type HostId = String;
        type ActorId = String;
        type Claims = ();

        fn resolve(
            &self,
            _host: &Self::HostId,
            _actor_id: &Self::ActorId,
        ) -> impl std::future::Future<Output = Result<Actor<Self::ActorId>, Error>> + Send {
            let actor = self.actor.clone();
            async move { Ok(actor) }
        }
    }

    let host = "h".to_string();
    let alice = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        alice.id().to_string(),
        (),
    );
    let signed = alice.sign_token(token).unwrap();

    let different_actor =
        Actor::<String>::with_verifying_key("different".to_string(), alice.verifying_key());
    let resolver = MismatchedResolver {
        actor: different_actor,
    };

    let result = block_on(resolver.verify(signed.jwt().to_string(), now));
    assert!(
        matches!(result, Err(Error::Auth(_))),
        "expected Err(Error::Auth(_)), got {:?}",
        result
    );
    if let Err(Error::Auth(msg)) = result {
        assert!(
            msg.contains("different actor"),
            "expected message containing 'different actor', got: {msg}"
        );
    }
}

#[derive(Clone, Debug)]
struct CustomContextBackend;

impl Falcon512Backend for CustomContextBackend {
    const FALCON_CONTEXT: &[u8] = b"other-protocol";
    fn generate() -> Result<Falcon512KeyPair, Error> {
        FalconBackend::generate()
    }

    fn sign(sk: &Falcon512PrivateKey, msg: &[u8]) -> Result<Falcon512Signature, Error> {
        use crate::sig::falcon::default_backend as dbe;
        use ::falcon::falcon::{
            FALCON_SIG_PADDED, falcon_sign_dyn_finish, falcon_sign_start, falcon_tmpsize_signdyn,
        };
        use ::falcon::shake::InnerShake256Context;
        use zeroize::Zeroizing;

        const LOGN: u32 = 9;
        const SIG_LEN: usize = sig::falcon::SIGNATURE_LEN;
        let mut rng = dbe::init_rng()?;

        let tmp_len = falcon_tmpsize_signdyn(LOGN);
        let mut tmp = Zeroizing::new(vec![0u8; tmp_len]);
        let mut sig = [0u8; SIG_LEN];
        let mut sig_len = SIG_LEN;

        let mut nonce = [0u8; 40];
        let mut hd = InnerShake256Context::new();
        let rc = falcon_sign_start(&mut rng, &mut nonce, &mut hd);
        if rc != 0 {
            return Err(Error::auth(format!("falcon-rs low-level error: {rc}")));
        }

        dbe::inject_domain_and_message(&mut hd, msg, Self::FALCON_CONTEXT);

        let rc = falcon_sign_dyn_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            FALCON_SIG_PADDED,
            sk.as_bytes(),
            &mut hd,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(Error::auth(format!("falcon-rs low-level error: {rc}")));
        }
        Falcon512Signature::from_bytes(&sig)
    }

    fn verify(pk: &Falcon512PublicKey, msg: &[u8], sig: &Falcon512Signature) -> Result<(), Error> {
        use crate::sig::falcon::default_backend as dbe;
        use ::falcon::falcon::{
            FALCON_SIG_PADDED, falcon_tmpsize_verify, falcon_verify_finish, falcon_verify_start,
        };
        use ::falcon::shake::InnerShake256Context;

        const LOGN: u32 = 9;

        let tmp_len = falcon_tmpsize_verify(LOGN);
        let mut tmp = vec![0u8; tmp_len];
        let sig_bytes = sig.as_bytes();

        let mut hd = InnerShake256Context::new();
        let rc = falcon_verify_start(&mut hd, sig_bytes);
        if rc != 0 {
            return Err(Error::auth(format!("falcon-rs low-level error: {rc}")));
        }

        dbe::inject_domain_and_message(&mut hd, msg, Self::FALCON_CONTEXT);

        let rc = falcon_verify_finish(
            sig_bytes,
            FALCON_SIG_PADDED,
            pk.as_bytes(),
            &mut hd,
            &mut tmp,
        );
        if rc != 0 {
            return Err(Error::auth(format!("falcon-rs low-level error: {rc}")));
        }
        Ok(())
    }

    fn from_bytes(secret: &[u8]) -> Result<Falcon512KeyPair, Error> {
        FalconBackend::from_bytes(secret)
    }
}

fn make_forged_jwt_with_context() -> (String, Actor<String>) {
    use base64::prelude::*;

    let keypair = FalconBackend::generate().unwrap();

    let verifier_actor = Actor::with_verifying_key(
        "alice".to_string(),
        VerifyingKey::new_falcon512(keypair.public.clone()),
    );

    let now = SystemTime::now();
    let token = Token::new(
        "example.com".to_string(),
        now,
        Duration::from_secs(30),
        "alice".to_string(),
        (),
    );

    let header_json =
        serde_json::to_string(&token::TokenHeader::for_alg(sig::AlgKind::Falcon512)).unwrap();
    let header_b64 = BASE64_STANDARD.encode(header_json.as_bytes());
    let body_b64 = BASE64_STANDARD.encode(serde_json::to_string(&token).unwrap().as_bytes());
    let message = format!("{header_b64}.{body_b64}");

    let sig = CustomContextBackend::sign(&keypair.private, message.as_bytes()).unwrap();
    let sig_b64 = BASE64_STANDARD.encode(sig.to_bytes());
    let jwt = format!("{message}.{sig_b64}");

    (jwt, verifier_actor)
}

#[test]
fn test_falcon_context_other_does_not_verify_as_rjwt() {
    use futures::executor::block_on;

    let (jwt, verifier_actor) = make_forged_jwt_with_context();
    let now = SystemTime::now();

    let mut resolver = TestResolver::new("example.com");
    resolver.add(verifier_actor);

    let result = block_on(resolver.verify(jwt, now));
    assert!(
        matches!(result, Err(Error::Auth(_))),
        "expected Err(Error::Auth(_)), got {:?}",
        result
    );
}

#[test]
fn test_alg_header_matches_actor_key_mismatch() {
    use futures::executor::block_on;

    let host = "example.com".to_string();
    let falcon = falcon_actor("alice");
    let now = SystemTime::now();

    let token = Token::new(
        host.clone(),
        now,
        Duration::from_secs(30),
        falcon.id().to_string(),
        (),
    );
    let signed = falcon.sign_token(token).unwrap();

    let ed25519_actor = Actor::with_verifying_key(
        "alice".to_string(),
        Actor::<String>::new("alice".to_string()).verifying_key(),
    );

    let mut resolver = TestResolver::new(host.clone());
    resolver.add(ed25519_actor);

    let result = block_on(resolver.verify(signed.jwt().to_string(), now));
    assert!(
        matches!(result, Err(Error::Auth(_))),
        "expected Err(Error::Auth), got {:?}",
        result
    );
}
