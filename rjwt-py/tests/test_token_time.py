import pytest
import rjwt


@pytest.mark.parametrize("invalid", [-1.0, float("nan"), float("inf"), 1e100])
def test_invalid_token_times_return_errors(invalid):
    host = "http://example.com"
    with pytest.raises(ValueError):
        rjwt.Token(host, invalid, 30.0, "actor", {})
    with pytest.raises(ValueError):
        rjwt.Token(host, 0.0, invalid, "actor", {})

    token = rjwt.Token(host, 0.0, 30.0, "actor", {})
    with pytest.raises(ValueError):
        token.is_expired(invalid)
    assert not token.is_expired(0.0)
    assert token.is_expired(31.0)


def test_signing_key_import_defaults_match_actor_construction():
    import asyncio
    import time

    original = rjwt.Actor("fixture-actor")
    restored = rjwt.Actor.with_keypair(original.id(), bytes(original.private_key_bytes()))
    public = rjwt.Actor.with_public_key(original.id(), bytes(original.public_key_bytes()))

    assert bool(restored.public_key_bytes() == original.public_key_bytes())
    assert not public.has_private_key()

    class Lookup:
        async def resolve(self, host, actor_id):
            return public

    async def verify_round_trip():
        now = time.time()
        token = rjwt.Token("http://example.test", now, 60.0, original.id(), {})
        signed = restored.sign_token(token)
        import base64
        import json

        expected = {"falcon512": "FN-DSA-512", "ed25519": "EdDSA"}[rjwt.DEFAULT_ALGORITHM]
        assert json.loads(base64.b64decode(signed.jwt().split(".")[0]))["alg"] == expected
        verified = await rjwt.Resolver(Lookup()).verify(signed.jwt(), now)

        assert verified.expires() == signed.expires()
        with pytest.raises(RuntimeError):
            await rjwt.Resolver(Lookup()).verify(signed.jwt(), now + 61.0)

    asyncio.run(verify_round_trip())

    with pytest.raises(ValueError):
        rjwt.Actor.with_public_key(original.id(), bytes(32))


def test_diagnostic_contract():
    import asyncio
    import base64
    import json

    marker = "synthetic_diagnostic_marker"
    actor = rjwt.Actor(marker)
    token = rjwt.Token("http://example.test", 0.0, 60.0, marker, {})
    signed = actor.sign_token(token)

    diagnostic = repr(signed)
    contains_material = signed.jwt() in diagnostic or marker in diagnostic
    assert not contains_material

    class Lookup:
        async def resolve(self, host, actor_id):
            raise AssertionError("structural rejection must precede lookup")

    header = base64.b64encode(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()).decode()

    async def verify_errors():
        for encoded in [marker, f"{header}.{marker}"]:
            with pytest.raises(RuntimeError) as error:
                await rjwt.Resolver(Lookup()).verify(encoded, 0.0)
            contains_material = marker in str(error.value)
            assert not contains_material

    asyncio.run(verify_errors())


def test_explicit_ed25519_creation_and_import():
    original = rjwt.Actor("explicit-actor", alg="ed25519")
    restored = rjwt.Actor.with_keypair(
        original.id(), bytes(original.private_key_bytes()), alg="ed25519"
    )
    public = rjwt.Actor.with_public_key(
        original.id(), bytes(original.public_key_bytes()), alg="ed25519"
    )
    assert restored.public_key_bytes() == original.public_key_bytes()
    assert public.public_key_bytes() == original.public_key_bytes()
