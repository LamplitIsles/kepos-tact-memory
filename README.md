# kepos-tact-memory

Local SQLite remote memory for [Tact](https://github.com/clabby/tact), published as a
[Kepos](https://github.com/LamplitIsles/kepos) HTTP service. The Kepos publisher with
`kind = "http"` strips all caller-supplied `Authorization` fields and injects exactly one
identity-bearing header:

```http
Authorization: Kepos <subscriber-public-key>
```

This server authenticates the device and resolves it to a Tact memory namespace through a
configured binding table. A namespace is a person or team; one person's several devices share
one namespace, and each device stays bound to exactly one namespace. No bearer tokens exist
on the server.

The service speaks Tact's remote-memory protocol (v1) — the same routes, wire types, bounds,
BM25 retrieval, optimistic concurrency, and error codes as the reference server — so an
unmodified Tact client works through Kepos unchanged.

## Protocol

Routes under `/v1/`:

| Method and path | Role | Contract |
| --- | --- | --- |
| `GET /v1/session` | reader | Protocol version, authenticated namespace, and role. |
| `POST /v1/memories/scan` | reader | BM25 search; at most five compact candidates. |
| `POST /v1/memories/read` | reader | Resolve exact visible keys (own and foreign namespaces). |
| `POST /v1/memories/list` | reader | Deterministic bounded window of visible records. |
| `POST /v1/memories/put` | writer | Insert or compare-and-swap replace in the device's namespace. |
| `POST /v1/memories/delete` | writer | Compare-and-swap delete in the device's namespace. |
| `POST /v1/memories/sync` | writer | Atomically reconcile the device's namespace to a snapshot. |
| `POST /v1/memories/export` | reader | Stable paginated snapshot in `(namespace, id)` order. |

Requests authenticate with `Authorization: Kepos <64-hex>` and assert the bound namespace
in `x-tact-memory-namespace`. A mismatched assertion is rejected with `403 namespace_mismatch`.
Devices absent from the binding table get `401 unauthorized`; reader bindings cannot mutate
(`403 forbidden`).

Storage is one SQLite file. Records are bounded per namespace: 1 KiB content, 512 records,
256 KiB aggregate content, seven days of unread probation (a successful read graduates a
record). Mutation, telemetry, and bound checks run in one Immediate transaction. IDs are never
reused after deletion or snapshot sync.

## Build

```sh
cargo build --release
# target/release/kepos-tact-memory
```

## Run

```sh
kepos-tact-memory \
  --config config.toml

# or, for a quick single-namespace setup:
kepos-tact-memory \
  --bind 127.0.0.1:8787 \
  --db memory/kepos-tact-memory.sqlite3 \
  --binding neil:c5a2168e17a53b699ced7e3f3c8470afd7f91b97a1582076c9797c3e024311a2,0d88922a7b6de68ca5011398c846f60de49129bc0d9592e0437b580c41a7e625
```

Bindings define who owns which namespace. The TOML form (`--config config.toml`, see
`config.example.toml`) supports roles and is the natural home for the table:

```toml
[[auth.bindings]]
namespace = "neil"
keys = ["<pubkey1>", "<pubkey2>"]   # neil's laptop and desktop share one namespace

[[auth.bindings]]
namespace = "bob"
role = "reader"                      # observers cannot mutate
keys = ["<pubkey3>"]
```

- `--binding NAMESPACE:KEY[,KEY...]` (repeatable): quick CLI bindings with writer role.
- A device may appear in at most one binding; a namespace may bind any number of devices.
- With no bindings every request returns `401`.

The listener defaults to `127.0.0.1:8787` and should stay loopback-only: the
`Authorization: Kepos ...` header is trustworthy only at the private publisher ingress —
anything that can reach the target directly can forge it.

## Publish via Kepos

Add a service to the publisher's TOML policy (`[publisher.services]`) and reload:

```toml
[[publisher.services]]
id = "tact-memory"
name = "Tact Memory"
kind = "http"
target_port = 8787
allow = ["<subscriber-public-key>", "<another-subscriber-public-key>"]
```

The subscriber gateway then presents `http://tact-memory.localhost:<gateway-port>/`. The
publisher rewrites every request's `Authorization` to `Kepos <subscriber-public-key>` before
forwarding to this server.

## Tact client configuration

Each person uses the namespace they are bound to — `neil` in the example above. Create a
private config (mode `0600`):

```toml
[memory]
enabled = true

[memory.remote]
endpoint = "http://tact-memory.localhost:17480/"
namespace = "neil"
bearer_token = "placeholder-not-used-behind-kepos"
workspace_roots = ["/absolute/path/to/team-project"]
```

Tact requires a non-empty `bearer_token`, but Kepos discards it and injects the device
identity; any placeholder works. The namespace must match the binding — read it from
`GET /v1/session`. Inside a configured workspace root Tact uses remote memory only; use
`tact memory push` / `tact memory pull` from any directory to transfer the local store.

## Verification

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

The suite covers the identity→namespace mapping, role policy, SQLite store semantics
(compare-and-swap, per-namespace deduplication and capacity, probation, snapshot sync, stable
export pagination), and the full HTTP contract exercised with exactly the headers a Kepos
publisher injects.

## Security notes

- The `Authorization: Kepos` header is a device assertion, not a secret. Its value is the
  subscriber's public key, so it must not be treated as a bearer secret — the Kepos peer
  connection and publisher allowlist are the real boundaries.
- Keep the listener on loopback. Do not bind `0.0.0.0`.
- The SQLite database is unencrypted; protect it like Tact's local store.
- Logs record operation, namespace, and role only — never content, headers, or keys.
