# kepos-tact-memory

Local SQLite remote memory for [Tact](https://github.com/clabby/tact), published as a
[Kepos](https://github.com/LamplitIsles/kepos) HTTP service. Each Kepos device gets its own
Tact memory namespace, derived from the subscriber identity Kepos injects into every request:

```http
Authorization: Kepos <subscriber-public-key>
```

The Kepos publisher with `kind = "http"` strips all caller-supplied `Authorization` fields
and replaces them with exactly that header. This server authenticates the device, maps its
identity to the namespace `kepos-<subscriber-public-key>`, and applies the configured role
policy. No bearer tokens exist on the server.

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

Requests authenticate with `Authorization: Kepos <64-hex>` and assert the derived namespace
in `x-tact-memory-namespace`. A mismatched assertion is rejected with `403 namespace_mismatch`.
Unknown devices get `401 unauthorized`; reader devices cannot mutate (`403 forbidden`).

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
  --bind 127.0.0.1:8787 \
  --db memory/kepos-tact-memory.sqlite3 \
  --allow c5a2168e17a53b699ced7e3f3c8470afd7f91b97a1582076c9797c3e024311a2 \
  --allow 0d88922a7b6de68ca5011398c846f60de49129bc0d9592e0437b580c41a7e625 \
  --readonly fb9782436a1d150879f65ec7d4a2281376499011df9fc45830c5459a92540d32
```

The same settings can live in a TOML file (`--config config.toml`); flags override the file.
See `config.example.toml`.

- `--allow`: Kepos public keys permitted to use the service (writers by default).
- `--readonly`: permitted keys restricted to `reader` (observers).
- `--allow-all`: authorize every valid Kepos key. Use only when the Kepos publisher
  allowlist is the authorization boundary and the listener is unreachable except through it.

With an empty policy every request returns `401`. The listener defaults to `127.0.0.1:8787`
and should stay loopback-only: the `Authorization: Kepos ...` header is trustworthy only at
the private publisher ingress — anything that can reach the target directly can forge it.

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

Each person uses their own namespace — the identity-derived `kepos-<their public key>`. Create
a private config (mode `0600`):

```toml
[memory]
enabled = true

[memory.remote]
endpoint = "http://tact-memory.localhost:17480/"
namespace = "kepos-c5a2168e17a53b699ced7e3f3c8470afd7f91b97a1582076c9797c3e024311a2"
bearer_token = "placeholder-not-used-behind-kepos"
workspace_roots = ["/absolute/path/to/team-project"]
```

Tact requires a non-empty `bearer_token`, but Kepos discards it and injects the device
identity; any placeholder works. The namespace must match the server-derived value — read it
from `GET /v1/session`. Inside a configured workspace root Tact uses remote memory only; use
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
