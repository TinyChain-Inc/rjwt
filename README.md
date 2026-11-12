# rjwt
Recursive Javascript Web Token libraries for Rust and Python

Signed-token diagnostics are opaque. Explicit accessors provide the encoded
representation and decoded claims when the caller requires them.

`Token::new` returns a `Result`: issue times must not precede the Unix epoch,
and expiry must fit the system clock. Verification checks decoded expiry before
constructing trusted claims. Python timestamp and TTL conversion rejects negative,
nonfinite, and out-of-range values instead of panicking. The token representation
and signature rules are unchanged.

Delegation retains the narrowest signed expiration; a child cannot renew its
parent's lifetime. Imported Ed25519 public keys reject weak keys, and verification
uses the cryptographic provider's strict API.

## Default algorithm

The `falcon` feature is enabled by default. Rust's typed `DEFAULT_ALGORITHM`
is `AlgKind::Falcon512` when enabled and `AlgKind::Ed25519` when disabled.
Python exposes its name as `"falcon512"` or `"ed25519"`.
Selection follows the build configuration; key-generation failures propagate.

Rust has one key-generation constructor, `Actor::new(id, algorithm)`, returning
`Result`. Pass `DEFAULT_ALGORITHM` for the build default or an explicit
`AlgKind::Ed25519` or `AlgKind::Falcon512` (with `falcon` enabled). This replaces
`new2` and the algorithm-specific constructor.

```rust
use rjwt_core::{Actor, AlgKind, DEFAULT_ALGORITHM};

let actor = Actor::new("default", DEFAULT_ALGORITHM)?;
let ed25519 = Actor::new("explicit", AlgKind::Ed25519)?;
# Ok::<(), rjwt_core::Error>(())
```

Python `Actor(id, alg=None)` uses the same default and accepts an explicit
`alg`, replacing the algorithm-specific factory. Python key imports also accept
an explicit `alg`; omission uses the default, never key-length inference.
Keys exported from default actors can be imported without specifying an algorithm.
