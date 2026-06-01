//! Falcon-512 (FN-DSA-512) variant of the recursive JWT chain example.

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, SystemTime};

use futures::executor::block_on;

use rjwt_core::{Actor, Error, Resolve, SignedToken, Token};

#[derive(Clone)]
struct Resolver {
    hostname: String,
    actors: HashMap<String, Actor<String>>,
    peers: Vec<Self>,
}

impl Resolver {
    fn new<A: IntoIterator<Item = Actor<String>>>(
        hostname: String,
        actors: A,
        peers: Vec<Self>,
    ) -> Self {
        Self {
            hostname,
            actors: actors.into_iter().map(|a| (a.id().clone(), a)).collect(),
            peers,
        }
    }
}

impl Resolve for Resolver {
    type HostId = String;
    type ActorId = String;
    type Claims = String;

    fn resolve(
        &self,
        host: &Self::HostId,
        actor_id: &Self::ActorId,
    ) -> impl Future<Output = Result<Actor<Self::ActorId>, Error>> + Send {
        let this = self;
        async move {
            if host == &this.hostname {
                this.actors
                    .get(actor_id)
                    .cloned()
                    .ok_or_else(|| Error::fetch(actor_id))
            } else if let Some(peer) = this.peers.iter().find(|p| &p.hostname == host) {
                Box::pin(peer.resolve(host, actor_id)).await
            } else {
                Err(Error::fetch(host))
            }
        }
    }
}

fn main() {
    let now = SystemTime::now();

    let bobs_id = "bob".to_string();
    let example_dot_com = "example.com".to_string();

    let actor_bob =
        Actor::new_falcon512(bobs_id.clone()).expect("falcon-rs available");
    let example = Resolver::new(example_dot_com.clone(), [actor_bob.clone()], vec![]);

    let retailer_dot_com = "retailer.com".to_string();
    let retail_app =
        Actor::new_falcon512("app".to_string()).expect("falcon-rs available");
    let retailer = Resolver::new(
        retailer_dot_com.clone(),
        [retail_app.clone()],
        vec![example.clone()],
    );

    let bank_account =
        Actor::new_falcon512("bank".to_string()).expect("falcon-rs available");
    let bank = Resolver::new(
        "bank.com".to_string(),
        [bank_account.clone()],
        vec![example, retailer.clone()],
    );

    let bobs_claim = String::from("I am Bob and retailer.com may debit my bank.com account");

    let bobs_token = Token::new(
        example_dot_com.clone(),
        now,
        Duration::from_secs(30),
        actor_bob.id().to_string(),
        bobs_claim.clone(),
    );

    let bobs_token = actor_bob.sign_token(bobs_token).expect("signed token");

    let bobs_token: SignedToken<String, String, String> =
        block_on(retailer.verify(bobs_token.into_jwt(), now)).expect("claims");

    assert!(bobs_token
        .claims()
        .get(&example_dot_com, &bobs_id)
        .expect("claim")
        .starts_with("I am Bob"));

    let retailer_claim = String::from("Bob spent $1 on retailer.com");
    let retailer_token = retail_app
        .consume_and_sign(bobs_token, retailer_dot_com.clone(), retailer_claim.clone(), now)
        .expect("signed token");

    assert_eq!(
        retailer_token
            .claims()
            .get(&retailer_dot_com, retail_app.id()),
        Some(&retailer_claim)
    );

    assert_eq!(
        retailer_token
            .claims()
            .get(&example_dot_com, actor_bob.id()),
        Some(&bobs_claim)
    );

    let retailer_token_as_received: SignedToken<String, String, String> =
        block_on(bank.verify(retailer_token.jwt().to_string(), now)).expect("claims");

    assert_eq!(retailer_token, retailer_token_as_received);

    assert!(retailer_token_as_received
        .claims()
        .get(&example_dot_com, &bobs_id)
        .expect("claim")
        .starts_with("I am Bob and retailer.com may debit my bank.com account"));

    assert!(retailer_token_as_received
        .claims()
        .get(&retailer_dot_com, retail_app.id())
        .expect("claim")
        .starts_with("Bob spent $1"));

    println!("OK: Falcon-512 chain verified — Bob → retailer.com → bank.com");
}
