from __future__ import annotations

import asyncio
import time

import rjwt


class ExampleResolver:
    def __init__(
        self,
        host: str,
        actors: dict[str, rjwt.Actor],
        peers: list[ExampleResolver] | None = None,
    ) -> None:
        self.host = host
        self.actors = actors
        self.peers: list[ExampleResolver] = peers or []

    async def resolve(self, host: str, actor_id: str) -> rjwt.Actor:
        if host == self.host:
            if actor_id in self.actors:
                return self.actors[actor_id]
            raise RuntimeError(f"Unknown actor: {actor_id}")
        for peer in self.peers:
            if peer.host == host:
                return await peer.resolve(host, actor_id)
        raise RuntimeError(f"Unknown host: {host}")


async def main() -> None:
    now = time.time()

    bob = rjwt.Actor("bob")
    example = ExampleResolver("http://example.com/", {"bob": bob})

    app = rjwt.Actor("app")
    retailer = ExampleResolver("http://retailer.com/", {"app": app}, peers=[example])

    bobs_claims = {"/home/bob": 0o755, "/tmp": 0o777}
    token = rjwt.Token("http://example.com/", now, 30.0, "bob", bobs_claims)
    bobs_token = bob.sign_token(token)

    verified = await rjwt.Resolver(example).verify(bobs_token.jwt(), now)
    assert verified.claims().get("http://example.com/", "bob") == bobs_claims

    app_claims = {"/orders/42": 0o644}
    retail_token = app.consume_and_sign(verified, "http://retailer.com/", app_claims, now)

    bank = ExampleResolver("http://bank.com/", {}, peers=[example, retailer])
    final = await rjwt.Resolver(bank).verify(retail_token.jwt(), now)

    assert final.claims().get("http://example.com/", "bob") == bobs_claims
    assert final.claims().get("http://retailer.com/", "app") == app_claims

    print("All assertions passed.")


asyncio.run(main())
