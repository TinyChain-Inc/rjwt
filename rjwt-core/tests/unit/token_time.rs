use super::*;

#[test]
fn invalid_native_times_return_errors() {
    assert!(matches!(
        Token::new(
            (),
            UNIX_EPOCH - Duration::from_secs(1),
            Duration::from_secs(1),
            (),
            ()
        ),
        Err(Error::Time(_))
    ));
    assert!(matches!(
        Token::new((), UNIX_EPOCH, Duration::MAX, (), ()),
        Err(Error::Time(_))
    ));
    let token = Token::new((), UNIX_EPOCH, Duration::from_secs(2), (), ()).unwrap();
    assert!(!token.is_expired(UNIX_EPOCH + Duration::from_secs(1)));
    assert!(token.is_expired(UNIX_EPOCH + Duration::from_secs(2)));
    assert!(token.is_expired(UNIX_EPOCH - Duration::from_secs(1)));
}

#[test]
fn decoded_expiry_cannot_overflow_the_system_clock() {
    let token: Token<(), (), ()> = serde_json::from_str(r#"{"iss":null,"iat":0,"exp":18446744073709551615,"actor_id":null,"custom":null,"inherit":null}"#).unwrap();
    assert!(!token.is_expired(UNIX_EPOCH));
    assert!(matches!(
        Claims::new(token.exp, (), (), ()),
        Err(Error::Time(_))
    ));
}

#[test]
fn delegated_claims_retain_the_narrowest_expiration() {
    let parent = Claims::new(100, (), (), ()).unwrap();
    let child = parent.consume(40, (), (), ()).unwrap();
    assert_eq!(child.expires(), UNIX_EPOCH + Duration::from_secs(40));
    assert!(matches!(
        child.clone().consume(41, (), (), ()),
        Err(Error::Time(_))
    ));
    let child = child.consume(20, (), (), ()).unwrap();
    assert_eq!(child.expires(), UNIX_EPOCH + Duration::from_secs(20));
}

#[test]
fn verified_delegation_and_subsequent_signing_preserve_attenuated_expiry() {
    use crate::{Actor, Resolve};

    struct Resolver(Actor<()>);

    impl Resolve for Resolver {
        type HostId = ();
        type ActorId = ();
        type Claims = ();

        fn resolve(
            &self,
            _: &(),
            _: &(),
        ) -> impl std::future::Future<Output = Result<Actor<()>, Error>> + Send {
            std::future::ready(Ok(self.0.clone()))
        }
    }

    futures::executor::block_on(async {
        let actor = Actor::new((), crate::AlgKind::Ed25519).unwrap();
        let parent = actor
            .sign_token(Token::new((), UNIX_EPOCH, Duration::from_secs(100), (), ()).unwrap())
            .unwrap();
        let mut child = Token::new((), UNIX_EPOCH, Duration::from_secs(40), (), ()).unwrap();
        child.inherit = Some(parent.jwt().to_owned());
        let child = actor.sign_token(child).unwrap();
        let resolver = Resolver(actor.clone());
        let verified = resolver
            .verify(child.jwt().to_owned(), UNIX_EPOCH + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(verified.expires(), UNIX_EPOCH + Duration::from_secs(40));
        let delegated = actor
            .consume_and_sign(verified, (), (), UNIX_EPOCH + Duration::from_secs(10))
            .unwrap();
        assert_eq!(delegated.expires(), UNIX_EPOCH + Duration::from_secs(40));
        assert!(
            resolver
                .verify(
                    delegated.jwt().to_owned(),
                    UNIX_EPOCH + Duration::from_secs(40)
                )
                .await
                .is_err()
        );
    });
}
