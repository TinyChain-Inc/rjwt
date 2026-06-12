# ADR-001: Post-Quantum Signature Algorithm Selection

## Status
Accepted

## Context
rjwt tokens are recursive — each level embeds the parent JWT in its payload,
re-encoding it through an additional base64 round. This causes geometric size
growth (base 4/3) per chain level, described by the recurrence:

    j(n) = F + (4/3) × (P + j(n-1))

where F is the per-algorithm fixed overhead (header + signature, base64) and
P is the base payload size. The 8 KB HTTP header limit constrains the viable
chain depth. Ed25519, the current signing algorithm, is vulnerable to Shor's
algorithm on a sufficiently capable quantum computer.

## Decision
Use Falcon-512 (NIST FIPS 206 / FN-DSA) as the post-quantum signature scheme.

## Consequences
- Single token: ~1.3 KB; depth-2 chain: ~5.2 KB — fits within the 8 KB limit
- Depth-3 chains (~8.3 KB) exceed the limit; this coincides with the practical
  maximum of 2–3 delegation hops in real deployments, so the constraint is not
  binding in practice
- The Gaussian sampler in the signing path requires careful implementation to
  avoid timing side-channel attacks

## Alternatives Considered

### ML-DSA-44 (FIPS 204)
Rejected. Signature size 2420 B means a depth-1 chain already exceeds 8 KB,
making any non-trivial delegation impractical.

### Falcon-1024 (FIPS 206)
Rejected. Provides 256-bit PQ security but signature size 1280 B limits viable
chains to depth 1. The extra security margin is not justified for the expected
2–3 hop delegation depth.

### SLH-DSA-SHA2-128s (FIPS 205)
Rejected. Signature size 7856 B exceeds the 8 KB transport limit for a single
token, making it completely impractical for HTTP header delivery regardless of
chain depth.
