# Build an independent application using Secure Net

**Secure Net is an open, independently governed communications protocol.**
Commonveil is its first adopting application, not a protocol owner, central
identity provider, mandatory relay or required application server.

A developer can integrate Secure Net into an independent website, mobile
app, desktop client or self-hosted service using the Rust core, the WebAssembly
interface, or their own implementation of the published CVP specifications.
The current AGPL-3.0-only licence still applies to the provided code.

## The boundary between protocol and product

| What you build | Who owns it |
| --- | --- |
| Actor keys, device documents and shared signed envelope formats | Secure Net specification and adopting device |
| Authenticated app login, UI, moderation and optional account billing | Each independent application |
| Encrypted session creation and recipient key verification | Secure Net compatible client code |
| User-scoped outbox, signed site-to-site delivery, mailbox collection | Each adopting site/relay under CVP-005, CVP-015 and CVP-019 |
| A Commonveil server, its legacy version 1 federation and its user database | Commonveil application only |

Do not require a Commonveil account to create a Secure Net actor. Do not
make a third-party app call Commonveil private API endpoints to deliver
CVP-019 messages. The protocol should keep working if Commonveil goes
offline or changes product priorities.

## Delivery: end to end

1. The sender's app verifies the recipient's independently signed actor
   document and active device keys (CVP-017), including key rotation.
2. The sending device creates a CVP-016 encrypted envelope for recipient
   devices and submits it to its own authenticated outbox, normally
   POST /cvp/v2/outbox.
3. The originating site validates ownership and permissions, queues delivery
   and authenticates POST /cvp/v2/deliver to the receiving site using CVP-005
   site signatures. When published by the destination, CVP-015 relay keys
   require post-quantum sealed site-to-site transport.
4. The recipient site verifies the request, nonce, digest and encryption
   compatibility, then stores only acceptable opaque envelopes in the
   recipient's mailbox (normally GET /cvp/v2/mailbox).
5. The receiving device authenticates and decrypts locally. Mail is removed
   only after intended devices acknowledge retrieval or retention expires.

A compatible relay sees recipients, sizes and timing, and a network observer
may see the communicating sites. Encrypting a message does not remove this
metadata. No server should receive plaintext direct messages, private KEM
seeds or history keys simply to make transport work.

Outbox, delivery and mailbox endpoint presence is **not** proof that those
requirements are implemented. An application must authenticate its own
clients, guard against replay and downgrade, enforce access rights, block
rules, quotas, retention and consistent durable receipts. The in-memory Rust
reference sites are examples, not production transport servers.

## Independent development checklist

- Read the full CVP-000 framework, CVP-002 signed records, CVP-005/015
  site authentication and sealed relay, CVP-016 sessions, CVP-017 actors,
  CVP-019 encrypted delivery and CVP-010 conformance documents.
- Run the core Rust reference tests: from the rust directory,
  cargo test -p secure-net-core --test social_e2e and
  cargo test -p secure-net-core --test third_party_apps.
- The third_party_apps test models two separate frontends, AuroraChat and
  LanternNotes, using separate identities and simulated sites; it exchanges
  device-decryptable private messages both ways and checks transport logs
  for plaintext. It reuses one shared Rust protocol implementation and
  an in-memory network. **It is not an independent-vendor HTTP test.**
- Independently implement an HTTPS server and durable storage, then connect
  two real apps from separately maintained codebases and databases. Verify
  both inbox and outbox paths, negotiated feature versions, signed request
  replay/rollback limits, request framing and a real CVP-015 sealed relay.
- Verify invalid and revoked actors, wrong devices, unsigned or corrupted
  envelopes, stale key histories, malicious relays, duplicates, lost acks,
  privacy leakage, offline/online resume, blocked actors and safe cleanup.
- Publicly propose changed wire formats through a numbered Secure Net
  Improvement Proposal. Approval requires the applicable human protocol
  review, separate from any application deployment.

## Discovery is still under review

The existing CVP-005 reference request signature begins with a historical
Commonveil-derived domain label and its site document uses an inherited
well-known path. These are **wire compatibility identifiers, not ownership
claims**. SNIP-0008 proposes a future brand-neutral discovery and signing
profile with explicit compatibility and downgrade rules. No application
should silently change signed bytes, rename trusted endpoints or declare
that unreviewed proposal implemented.

## Protocol maturity

The common Rust library includes experimental portable identity and KEM
device-consent helpers from SNIP-0007. They are not an approved identity
migration standard, and neither Commonveil nor another application should
enable production account cutover until an independent human cryptographic
review and an interoperable multi-host import/rollback implementation exist.

This is a practical **development reference**, not a security audit or a
claim that Commonveil's hosted site already interoperates with arbitrary
third-party apps.
