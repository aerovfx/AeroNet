# AeroNet — a connectivity layer for the Agent era

Today's Internet was built to connect **devices**, distribute **web pages**
and present information to **humans**. AI agents, however, need to identify
each other, exchange structured data, prove provenance, negotiate access and
coordinate toward shared goals.

**AeroNet** is a Rust experiment that builds that connectivity layer. The
project does not replace fiber, TCP/IP or the physical Internet. It starts by
adding the layers a machine-first network needs: self-sovereign identity,
semantic messages, verifiable permissions, data validity windows and audit
trails.

![Layers of today's Internet compared with an AI-native Internet](docs/assets/aeronet-layers.png)

## What is today's Internet missing?

The Internet is not a single technology but many layers developed over
decades. Those layers have served humans very well, yet many of their core
assumptions no longer hold when the communicating parties are autonomous
agents.

### Identity is tied to location

An IP address describes where a process currently appears; DNS maps a name to
that location. Neither proves who is actually communicating. For agents that
run in short-lived containers, migrate between clouds or act on behalf of
users, addresses change constantly while identity needs to stay durable.

### The wire understands bytes, not intent

TCP and UDP move data without knowing whether it is a request, a proposal,
evidence or a result. HTTP mostly describes operations on resources, not the
full goal, constraints, budget and deadline of a task. Every application
therefore has to rebuild semantics and coordination rules on top.

### Trust is centralized and hard to audit

TLS protects the wire but depends on the CA system. It cannot answer who
authorized an agent, where data originated, which relays it passed through,
or whether content was altered after leaving the sender. When agents can make
their own decisions, "connected" is not the same as "trustworthy enough to
act on".

### Data is presented for human eyes

Most of the Web revolves around HTML, visual interfaces and free-form text.
Agents must re-infer structure through scraping or NLP, losing context and
provenance along the way. Data rarely declares its validity window, so a fact
that was true yesterday keeps being used as if it were still true today.

### Access control relies on convention

`robots.txt`, terms of service and rate limits are mostly application-level
policy. They travel poorly with the data and are hard to prove across
organizations. Agents need cryptographically checkable permissions: who
granted them, to whom, for which actions, on which resources, for how long
and how many times.

### Economic incentives ignore machine-readable data

Today's Web rewards page views, advertising and human attention. Providers
have little incentive to publish clean, schema-rich data with provenance for
machines. An agent economy needs to price the data, tools or tasks that are
actually consumed.

## Why was AeroNet started?

AeroNet began with a small question: **if agents are first-class citizens of
the network, how should they talk to each other?**

Instead of forcing every agent to know in advance the address, bespoke API
and private format of every other agent, AeroNet aims for a more flexible
connectivity layer:

- Identity is derived from a public key and survives endpoint changes.
- Every message carries its own schema, intent, validity window, provenance
  and signature.
- Tasks describe the desired outcome with constraints, budget and deadline,
  rather than a rigid endpoint call.
- Recipients grant specific capabilities; relays can enforce permissions
  before forwarding a message.
- Knowledge objects declare their ontology and validity window so receivers
  know whether the data still applies.
- An audit trail lets humans or other agents review the exchange later.

The destination is a network where agents can be discovered, authenticated,
connected and coordinated regardless of where they run or which model they
use. AeroNet is currently a seed of that direction, not a claim that the
AI-native Internet is solved.

## Current foundation

| Component | Role |
|---|---|
| Agent DID | `did:aeronet:<base58(sha256(ed25519_public_key))>`, decoupling identity from network location |
| Challenge-response | The broker only registers an endpoint after the agent proves possession of its private key |
| Signed envelope | Messages carry schema, sender, recipient, intent, TTL, payload and an Ed25519 signature |
| Capability token | Bounds grantee, audience, actions, expiry and total message count |
| Task contract | Goal, constraints, compute budget, deadline and output schema |
| Knowledge object | Data with ontology, confidence, `valid_from`, `valid_until` and `superseded_by` |
| Durable store | SQLite WAL persists replay state, capability usage and the offline queue |
| Transport encryption | Every WebSocket link runs a Noise_NN handshake before any application data, with the handshake hash bound into the signed auth proof |
| Broker | Resolver/relay that enforces policy, restores pending messages and writes a JSONL audit log |
| Federation | A broker dials its configured peers exactly like an agent would; if a recipient isn't connected locally, the envelope is forwarded to every peer and still queued durably |
| Agent runtime | Signed delivery ACKs, an Anthropic adapter and an `echo` mode |

```text
src/
├── identity.rs       DIDs, key storage, Ed25519 signing and verification
├── capability.rs     capability tokens
├── protocol.rs       auth proofs, envelopes, tasks and knowledge objects
├── storage.rs        persistent queue, replay state and capability quotas
├── transport.rs      Noise_NN session wrapping the WebSocket link
└── bin/
    ├── broker.rs     WebSocket resolver/relay + policy enforcement
    ├── agent.rs      agent runtime + model adapters
    └── key.rs        CLI for key generation and token issuance
```

## Trying it on localhost

### 1. Build and create identities

```bash
cargo build
cargo run --bin aeronet-key -- generate --out alice.key.json
cargo run --bin aeronet-key -- generate --out bob.key.json
```

Each `generate` command prints the agent's DID. Export both values in your
shell:

```bash
ALICE_DID='did:aeronet:...'
BOB_DID='did:aeronet:...'
```

### 2. Grant permissions in both directions

Bob grants Alice the right to message Bob, and vice versa:

```bash
cargo run --bin aeronet-key -- issue \
  --issuer-key bob.key.json --grantee "$ALICE_DID" --out alice-to-bob.cap.json

cargo run --bin aeronet-key -- issue \
  --issuer-key alice.key.json --grantee "$BOB_DID" --out bob-to-alice.cap.json
```

### 3. Start the broker

```bash
RUST_LOG=info cargo run --bin broker
```

By default the broker listens on `127.0.0.1:8787`, writes the audit log to
`conversation.jsonl` and delivery state to `aeronet.db`. Both locations can
be changed with `--audit-log <path>` and `--state-db <path>`. The audit log
and the queue both survive restarts.

The sending agent may connect before the recipient. The broker stores the
task and forwards it once the recipient authenticates. A message only leaves
the queue after a valid ACK.

### 4. Start the waiting agent

```bash
cargo run --bin agent -- \
  --key bob.key.json --peer "$ALICE_DID" \
  --capability bob-to-alice.cap.json --provider echo --max-turns 3
```

### 5. Send the first task

```bash
cargo run --bin agent -- \
  --key alice.key.json --peer "$BOB_DID" \
  --capability alice-to-bob.cap.json --provider echo --max-turns 3 \
  --kickoff "Propose a data quality assurance plan" \
  --constraint "no PII,only sources with provenance" \
  --budget-units 100
```

To use a real model, set `ANTHROPIC_API_KEY`, replace `--provider echo` with
`--provider anthropic` and optionally pass `--model <model-id>`.

### 6. Federate two brokers (optional)

A broker can forward envelopes to a second broker when the recipient isn't
connected locally. Give each broker its own identity and list the other as a
peer, symmetrically:

```bash
cargo run --bin aeronet-key -- generate --out broker-x.key.json
cargo run --bin aeronet-key -- generate --out broker-y.key.json
BROKER_X_DID='did:aeronet:...'
BROKER_Y_DID='did:aeronet:...'

cargo run --bin broker -- --listen 127.0.0.1:8787 --state-db x.db \
  --audit-log x.jsonl --broker-key broker-x.key.json \
  --peer-broker "ws://127.0.0.1:8788@$BROKER_Y_DID"

cargo run --bin broker -- --listen 127.0.0.1:8788 --state-db y.db \
  --audit-log y.jsonl --broker-key broker-y.key.json \
  --peer-broker "ws://127.0.0.1:8787@$BROKER_X_DID"
```

Each broker dials the other exactly like an agent would — same Noise
handshake, same signed DID auth proof. Since both sides configure and dial
each other, the pair ends up mutually authenticated: each direction proves
the identity of whichever side initiated it. Point Alice at broker X and Bob
at broker Y (`--broker 127.0.0.1:8788`); a task Alice sends to Bob is
forwarded across the federation link and Bob's reply comes back the same
way, with each broker still queuing its own durable copy as a fallback.

## Current limitations

AeroNet is an application-layer MVP, not yet a complete distributed network:

- The WebSocket demo binds to localhost only. Every link is now wrapped in a
  Noise_NN session (forward-secret, authenticated-encrypted) with the
  handshake hash bound into the signed DID auth proof, so an active
  man-in-the-middle splicing two separate Noise sessions is detected and
  rejected. This protects the wire; it does not yet replace WSS/mTLS for
  deployments that need certificate-based trust or public CA compatibility.
- Federation is a statically configured, single-hop full mesh: every broker
  must list every peer it wants to reach directly, and a peer that isn't
  connected locally to *any* configured broker in the mesh is unreachable.
  There is no DHT, iterative lookup, multi-hop routing, route attestation or
  reputation yet. Forwarding is also best-effort broadcast to all peers, so a
  message can occasionally be queued durably on more than one broker if the
  recipient never claims it from some of them (harmless — those copies
  self-expire via the existing TTL cleanup).
- A broker only cryptographically proves the identity of whichever side
  *dialed* a given federation link, the same address-based trust an agent
  already places in `--broker <addr>`. A pair of brokers that both list each
  other ends up mutually authenticated by their two separately-dialed links,
  but a single one-way link does not, by itself, prove who answered the
  configured URL.
- Delivery is currently **at-least-once**; agents ACK automatically, but
  there is no backoff-based retry scheduler or dead-letter queue.
- Replay state, the pending queue and capability quota usage are each
  tracked per broker with no replication, compaction policy or consensus
  across the mesh. A capability's `max_messages` is therefore enforced
  independently by every broker it happens to route through, not as one
  global count.
- Capability quotas are durable, but there is no revocation registry or
  delegation chain yet.
- The cost field is only an extension point; no payment channel or ledger is
  integrated.
- There is no web-of-attestation or threshold governance across
  organizations yet.

These limitations also define the roadmap: encryption by default, federated
registries, distributed delivery, auditable routes, multi-source trust and
direct value exchange between agents.

## Testing

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The tests cover signatures after payload tampering, tokens used by the wrong
agent, expired messages, replay, queue recovery after restart, signed ACKs,
and the Noise transport (matching channel binding between both sides and
rejection of tampered ciphertext). Federation itself is network/IO-heavy
broker glue rather than pure logic, so it is verified with a real two-broker
smoke test (see step 6 above) rather than unit tests.

## Building AeroNet together

AeroNet is open source. Developers may use, study, modify, distribute and
build products on top of this codebase under the MIT terms.

Priority contribution areas include transport encryption, federated
DHT/registries, multi-relay routing, persistent delivery, capability
revocation, web-of-trust, SDKs and model adapters. Before submitting a
change, please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

The project is released under the [MIT License](LICENSE), copyright © 2026
VietChung. The license allows commercial and non-commercial use, copying,
modification, distribution and sublicensing, provided the copyright and
license notices are preserved.

## Author

**VietChung** · Ho Chi Minh City<br>
Published at: **20:24 (UTC−12:00)**<br>
ORCID: [0009-0005-4767-9967](https://orcid.org/0009-0005-4767-9967)

- Website: [aerovfx.com](https://aerovfx.com/)
- Facebook: [vietchung](https://facebook.com/vietchung)
- X: [@vietchung](https://x.com/vietchung)
- LinkedIn: [in/vietchung](https://www.linkedin.com/in/vietchung/)
- Hugging Face: [aerovfx](https://huggingface.co/aerovfx)

Full author information lives in [AUTHORS.md](AUTHORS.md).
