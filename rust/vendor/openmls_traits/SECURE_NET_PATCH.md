# Secure Net patch

A copy of the crates.io release with one change: the ciphersuite
`MLS_256_XWING_AES256GCM_SHA512_MLDSA87` (code point 0x0057, the value ts-mls uses) is added,
built only from primitives this crate already has: X-Wing (HPKE KEM 0x647a), AES-256-GCM,
HKDF-SHA512 and ML-DSA-87. Search for `MLS_256_XWING_AES256GCM_SHA512_MLDSA87` to see every
line changed. Licence unchanged: MIT, in `LICENSE` (copied from the OpenMLS repository). Drop this copy once the suite is
assigned an IANA code point and supported upstream.
