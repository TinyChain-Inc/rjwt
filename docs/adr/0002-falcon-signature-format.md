# ADR-002: Falcon-512 Signature Encoding Format

## Status
Accepted

## Context
FIPS 206 / FN-DSA defines three on-wire encodings of the same underlying signature.
The byte length for FN-DSA-512 (logn = 9) depends on the chosen encoding:

| Encoding   | falcon-rs constant       | Size (FN-DSA-512)        |
|------------|--------------------------|--------------------------|
| COMPRESSED | `FALCON_SIG_COMPRESSED`  | variable, max 752 B      |
| PADDED     | `FALCON_SIG_PADDED`      | fixed, exactly 666 B     |
| CT         | `FALCON_SIG_CT`          | fixed, exactly 809 B     |

PADDED is the size cited throughout the FIPS 206 spec and across cross-implementation
documentation; it is the canonical interop encoding. ADR-001's chain-size budget
("Single token: ~1.3 KB; depth-2 chain: ~5.2 KB") is derived assuming this 666-byte
signature length.

The `lattice-safe/falcon-rs` crate exposes all three encodings via the low-level
`falcon` module's `sig_type: i32` parameter. Its high-level SDK (`FnDsaKeyPair::sign`)
defaults to COMPRESSED without surfacing the format selector. A naive integration that
calls the SDK directly therefore produces variable-length COMPRESSED signatures, which
breaks both ADR-001's size math and cross-implementation interop.

## Decision
Use `FALCON_SIG_PADDED` (666 bytes fixed for FN-DSA-512) by calling the low-level
`falcon-rs` API (`falcon::falcon_sign_dyn` / `falcon_sign_tree`) with an explicit
`sig_type = FALCON_SIG_PADDED`.

## Consequences
- Exact length validation at the type boundary: `Falcon512Signature` is a
  `Box<[u8; 666]>`, and any other length is rejected at `from_bytes` rather than
  surfacing later as a verify failure.
- Cross-implementation interop: signatures verify against any FIPS 206 implementation
  that accepts the standard PADDED encoding (PQClean, pqcrypto-falcon, etc.).
- ADR-001's depth-2 chain-size budget (~5.2 KB under the 8 KB HTTP-header limit)
  holds verbatim.
- The default `FalconRsBackend` cannot use the convenience `FnDsaKeyPair::sign`
  prelude method and must drop to the low-level `falcon` module to pass the explicit
  `sig_type` parameter.

## Alternatives Considered

### FALCON_SIG_COMPRESSED
Rejected. Smallest average signature size, but variable-length — the only achievable
length check is a loose range (≥ 41 B header overhead, ≤ 752 B maximum), which is too
weak a boundary for a wire-format type. Worst-case 752 B also erodes ADR-001's depth-2
chain-size margin. Not the FIPS 206 standard interop format.

### FALCON_SIG_CT
Rejected. The CT encoding protects against a timing side-channel that leaks
information about the signature value through the verifier's coefficient-decoding
path. This protection has a payoff only when the signed message is itself secret and
low-entropy, and the "public" key is not publicly distributed — a threat model that
does not apply to JWT payloads, which are transmitted over the wire in plaintext. CT
also costs an additional 143 bytes per signature (809 vs. 666) for no defensive
benefit in this protocol and is not the FIPS 206 standard interop format.
