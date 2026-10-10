# @latticeagi/commit

`commit` is the LatticeAGI **Commit zone core**: M-of-N quorum-authorized
conditional value transfers ("commits") with escrow custody, deadlines, and
disputes — protocol `commit/1`, simulation custody profile `sim-ledger/1`.

A commit is an envelope (payer, payee, amount, deadline ladder, condition
clauses) that must collect a threshold of Ed25519 approvals before it can be
executed. On execution, funds move into escrow (`EscrowHeld`); evidence
satisfying the envelope's clauses moves the commit to `RELEASE_PENDING`, and
after the challenge window the ledger settles it (`SETTLED`) — or a dispute
diverts it to arbitration. Every state transition is journaled as a
hash-chained event log, and any commit can be exported as a self-contained
**proof bundle** that a verifier can check offline — integrity, authorization,
and execution receipts — with no access to the daemon.

Zero runtime dependencies. TypeScript that runs under Node's native type
stripping — no transpile step needed to run it, `tsc` is only used for
typechecking and producing `dist/`.

## Requirements

- Node.js **>= 22.18** (native `--experimental-strip-types`, i.e. it just runs `.ts`)
- `npm install` (dev-only deps: typescript, @types/node)

## Install / build / test

```bash
npm install            # dev deps only; there are no runtime dependencies
node bin/commit --version      # runs src/cli.ts directly via type stripping
npm run typecheck      # tsc --noEmit
npm run build          # emits dist/ (bin/commit prefers dist/ when present)
npm test               # node --test test/*.test.ts
npm run ci             # typecheck + test
```

To get a `commit` binary on PATH: `npm link` (or `npm install -g .`) — the
package exposes `bin/commit`. Throughout this README we invoke
`node /path/to/repo/bin/commit`; both `bin/commit` and `node src/cli.ts`
are valid entry points (`bin/commit` prefers `dist/` when built).

## What it does

- **Objects**: signed/canonical JSON artifacts (envelope, policy, approvals,
  attestations, evidence, awards, blobs) with JCS canonical bytes and
  domain-separated digests `D(kind, body) = sha256("LAGI-COMMIT/"+kind+"/1\0"+JCS(body))`.
- **Coordinator daemon**: `commit serve` exposes JSON-RPC over a **unix socket**;
  calls carry a `request_id` (idempotent mutation replay) and a **capability**
  bound to the caller's OS uid (see "Capabilities & uids" below).
- **Custody**: `sim-ledger/1` is an in-daemon simulated ledger — execute holds
  escrow synchronously and settles after the challenge window.
  `certified-escrow/1` and `mode = "live"` are **Covenant v1 gates** and
  intentionally throw `NotImplementedSurface` (see "Surface gates").
- **Proof bundles**: `commit export` writes `manifest.json` + `objects/*.json`;
  `commit verify` re-checks digests, signatures, quorum rules, and custody
  receipts against a `trust.json` anchor — fully offline.

## Trust anchoring (important)

`commit verify` and `commit store verify` fail `TRUST_UNANCHORED` unless the
bundle/store was produced under a `trust.json` whose `reducer_digest` equals
this build's reducer identity. For this implementation that is:

```
reducer_digest = sha256("commit-reducer/1")
               = 03144a1230636a600478f185ad50b08d0be444303288887eee91d02d337018bf
```

Do **not** hand-write `trust.json` — use `commit trust init`, which hashes the
reducer identity itself and fills in every anchor field:

```bash
node bin/commit trust init \
  --policy-file policy.json \
  --custody-manifest custody.json \
  --writer-key-file keys/writer/public.key \
  [--custody-key-file keys/receipt/public.key] \  # defaults to manifest receipt_key
  [--writer-epoch 1] \
  [--reducer commit-reducer/1 | --reducer-digest <64-hex>] \  # default: commit-reducer/1
  --out trust.json
```

`--reducer <name>` hashes a reducer identity string for you
(`sha256(name)`); `--reducer-digest` accepts a precomputed digest for
third-party reducers. `genesis_policy_hash` / `custody_manifest_hash` are the
`D("policy", …)` / `D("custody_manifest", …)` digests — the same values
`commit canonicalize` prints.

## Capabilities & uids

The unix-socket RPC layer grants **at most one capability per peer OS uid**
(`capsByUid`): each `[[principals]]` entry in `commit.toml` binds one local
`uid` → one `principal` → one `capability` id, its allowed methods/object
kinds/commit_ids/max_amount, and an expiry. Connecting with the wrong `--cap`,
an unlisted uid, or a method outside the capability fails `FORBIDDEN` /
`UNAUTHENTICATED`; a second `[[principals]]` entry for the same uid is a
startup-time config error.

**Implication for real deployments**: because uid is the authentication unit,
each principal that needs a distinct capability must connect from its own OS
user (service account). The quickstart below gives your own uid (`id -u`) a
single wide capability for demo purposes — that's fine for simulation, not a
production shape.

## `commit sign` — offline signer, deterministic-seed refusal

`commit sign` signs approval/attestation/award/control/migration bodies. The
seed is read via `--key-fd N` (file descriptor, 64 lowercase hex chars = 32
bytes); the public output is `{key_id, sig}` and the signature binds
`"LAGI-COMMIT-SIGN/"+kind+"/1"` over the body digest.

Two documented behaviors:

- **Fixture-seed refusal**: seeds made of a single repeated byte
  (`00…00`, `01…01`, …) are refused with `UNAUTHENTICATED`. The published
  conformance fixtures (`test/fixtures.ts`) generate keys exactly this way
  (`Buffer.alloc(32, i)`); deterministic public seed material must never sign
  live bodies. Real key material from `commit keygen` is never rejected.
- **Slot journal**: with `--journal-dir`, a durable per-(key_id, kind, slot)
  journal refuses to sign a *different* body for the same decision slot
  (`SIGNATURE_INVALID`), but replays the same signature for an identical body
  (idempotent retries are safe).

## Surface gates (Covenant v1)

These exist by design; encountering them is not a bug:

- `mode = "live"` — `commit init`/`serve` throw `NotImplementedSurface`
- `profile = "certified-escrow/1"` — custody operations throw
  `NotImplementedSurface`; config requires a non-empty `egress_allowlist`
- `mode = "live"` combined with `sim-ledger/1` is rejected at config parse
- Envelope `purpose` free-text is bounded; some object kinds are gated

## Quickstart (full E2E, sim-ledger/1)

Copy-paste on a clean clone. Requires `bash`, `jq`, `sha256sum`, `node >=22.18`.
Sets up a 2-of-3 approve quorum (alice mandatory), a 2-of-2 attest quorum,
then: init → serve → propose → 2 approvals → execute → EscrowHeld → evidence →
auto-settle → balances → export → verify → store verify.

```bash
set -euo pipefail
REPO=/path/to/commit            # <-- set this to your clone
C="node $REPO/bin/commit"
W=/tmp/commit-quickstart
rm -rf "$W"; mkdir -p "$W"/{keys,journal,proofs,store}
cd "$W"
SOCK="$W/commit.sock"
CAP=cap_alice
J() { jq -r "$1"; }

# --- keys: writer (daemon), receipt (custody receipts), quorum members ---
for k in writer receipt k1 k2 k3 k4 k5; do $C keygen --out "keys/$k" >/dev/null; done
pub() { tr -d '\n' < "keys/$1/public.key"; }
```

### policy.json — quorum rules, limits, asset

```bash
cat > policy.json <<EOF
{
  "v": 1, "policy_id": "pol1", "tenant": "lab1", "environment": "simulation",
  "custody": "sim1",
  "asset": {"code": "SIMUSD", "scale": 2, "custody": "sim1"},
  "members": [
    {"key_id": "k1", "principal": "alice",    "kind": "human",   "public_key": "$(pub k1)"},
    {"key_id": "k2", "principal": "bob",      "kind": "human",   "public_key": "$(pub k2)"},
    {"key_id": "k3", "principal": "carol",    "kind": "service", "public_key": "$(pub k3)"},
    {"key_id": "k4", "principal": "dana",     "kind": "service", "public_key": "$(pub k4)"},
    {"key_id": "k5", "principal": "eli",      "kind": "service", "public_key": "$(pub k5)"}
  ],
  "approve":   {"threshold": 2, "keys": ["k1", "k2", "k3"], "mandatory_principals": ["alice"]},
  "attest":    {"threshold": 2, "keys": ["k4", "k5"],       "mandatory_principals": []},
  "arbitrate": {"threshold": 1, "keys": ["k3"],             "mandatory_principals": []},
  "control":   {"threshold": 1, "keys": ["k3"],             "mandatory_principals": []},
  "max_amount_minor": "50000", "max_exposure_minor": "100000",
  "daily_commit_minor": "100000", "max_duration_ms": "2592000000",
  "min_challenge_ms": "1000",
  "rules_digest": "$(printf 'rules-v1' | sha256sum | cut -d' ' -f1)"
}
EOF
```

### custody.json — sim-ledger manifest

```bash
cat > custody.json <<EOF
{
  "v": 1, "custody": "sim1", "profile": "sim-ledger/1",
  "asset": {"code": "SIMUSD", "scale": 2, "custody": "sim1"},
  "implementation_digest": "$(printf 'sim-ledger/1' | sha256sum | cut -d' ' -f1)",
  "receipt_key": "$(pub receipt)",
  "idempotency_min_ms": "2592000000",
  "authoritative_lookup": true, "atomic_allocation": true, "fencing": true,
  "retry_mode": "never"
}
EOF
```

### trust.json — via `commit trust init` (hashes the reducer identity for you)

```bash
POLICY_HASH=$($C canonicalize --kind policy --file policy.json | J .digest)
$C trust init --policy-file policy.json --custody-manifest custody.json \
  --writer-key-file keys/writer/public.key --custody-key-file keys/receipt/public.key \
  --out trust.json >/dev/null
```

### commit.toml — daemon config (note: [[principals]] uid = your OS uid)

```bash
cat > commit.toml <<EOF
version = 1
mode = "simulation"
tenant = "lab1"
listen = "unix:$SOCK"
store = "$W/store"
policy_object = "pol1"
trust_file = "$W/trust.json"
custody_manifest_file = "$W/custody.json"
writer_key_ref = "file:$W/keys/writer/secret.key"
writer_epoch = "1"
max_frame_bytes = 1048576
max_blob_bytes = 1048576
max_inflight_requests = 16
max_objects_per_principal = 10000
max_unbound_object_bytes = "104857600"
request_timeout_ms = 10000
clock_max_skew_ms = "300000"
timer_poll_ms = 200
clock_source = "host-synchronized"
proof_directory = "$W/proofs"
audit_socket = "none"
audit_delivery = "optional-local-outbox"

[storage]
schema = 1
journal_mode = "WAL"
synchronous = "FULL"
busy_timeout_ms = 5000
min_free_bytes = "0"
backup_interval_ms = "3600000"
retain_unresolved = true
retain_economic_days = 30

[custody]
profile = "sim-ledger/1"
credential_ref = "none"
egress_allowlist = []
lookup_interval_ms = 100
max_lookup_interval_ms = 1000
max_attempts = 3

[[principals]]
uid = $(id -u)
principal = "alice"
capability = "$CAP"
methods = ["object.put", "object.get", "promise.propose", "promise.get", "promise.list",
           "approval.submit", "promise.commit", "promise.cancel", "condition.submit",
           "dispute.open", "dispute.resolve", "promise.advance", "custody.reconcile",
           "custody.retry", "account.get", "event.list", "proof.export", "proof.verify",
           "control.apply", "control.status", "health.get"]
object_kinds = ["envelope", "approval", "evidence", "award", "blob", "control", "custody"]
commit_ids = ["c1"]
max_amount_minor = "50000"
expires_ms = "4102444800000"

[[sim_accounts]]
principal = "alice"
available = "100000"

[[sim_accounts]]
principal = "merchant"
available = "0"
EOF
```

### init + serve + health

```bash
$C init --config commit.toml --policy-file policy.json --trust-file trust.json \
  --custody-manifest custody.json --out store --receipt-key-file keys/receipt/secret.key

nohup $C serve --config commit.toml >serve.log 2>&1 & echo $! > serve.pid
for i in $(seq 1 50); do
  $C --json health --socket "$SOCK" --cap "$CAP" >/dev/null 2>&1 && break
  sleep 0.2
done
$C --json health --socket "$SOCK" --cap "$CAP"      # {"ok":true,...} when ready
```

### envelope + propose

```bash
NOW=$(date +%s%3N)
cat > envelope.json <<EOF
{
  "v": 1, "tenant": "lab1", "environment": "simulation",
  "commit_id": "c1", "business_id": "inv-1",
  "payer": "alice", "payee": "merchant",
  "custody": "sim1",
  "asset": {"code": "SIMUSD", "scale": 2, "custody": "sim1"},
  "amount_minor": "10000",
  "policy_hash": "$POLICY_HASH",
  "nonce": "$(printf 'a%.0s' $(seq 1 32))",
  "created_ms": "$NOW",
  "commit_by_ms": "$((NOW + 300000))",
  "fund_by_ms": "$((NOW + 600000))",
  "condition_by_ms": "$((NOW + 900000))",
  "challenge_ms": "2000",
  "dispute_ms": "60000",
  "dispute_fallback_pay_minor": "0",
  "condition": {"kind": "all", "clauses": [
    {"id": "delivery", "kind": "attested", "predicate": "delivery.accepted", "authority": "attest"}
  ]},
  "purpose": "invoice settlement demo",
  "parents": []
}
EOF
ENV_HASH=$($C canonicalize --kind envelope --file envelope.json | J .digest)
R()  { $C "${@:2}" --socket "$SOCK" --cap "$CAP"; }
RM() { $C "${@:2}" --socket "$SOCK" --cap "$CAP" --request-id "$1"; }

RM r_env1 object put --id env1 --kind envelope --file envelope.json
RM r_prop1 propose --envelope-object env1          # rev 1, state PROPOSED
```

### sign + submit 2 approvals (2-of-3 quorum, alice mandatory = k1)

```bash
for k in k1 k2; do
  cat > "body_$k.json" <<EOF
{"v":1,"tenant":"lab1","environment":"simulation","commit_id":"c1",
 "envelope_hash":"$ENV_HASH","policy_hash":"$POLICY_HASH","key_id":"$k","decision":"approve"}
EOF
  $C sign --kind approval --body-file "body_$k.json" --key-fd 3 \
    --key-id "$k" --journal-dir journal --out "sig_$k.json" 3<"keys/$k/secret.key" >/dev/null
  jq -n --slurpfile b "body_$k.json" --slurpfile s "sig_$k.json" \
    '{body: $b[0], signature: $s[0].sig}' > "approval_$k.json"
  RM "r_put_$k" object put --id "va_$k" --kind approval --file "approval_$k.json"
done
RM r_ap1 approve --id c1 --approval-object va_k1 --expected-revision 1   # rev 2
RM r_ap2 approve --id c1 --approval-object va_k2 --expected-revision 2   # rev 3 → APPROVED
```

### execute → EscrowHeld → evidence → satisfy → auto-settle

```bash
RM r_exec execute --id c1 --expected-revision 3
# → state ACTIVE, events [CommitAuthorized, EscrowHeld] (sim-ledger holds escrow synchronously)

NOW=$(date +%s%3N)
cat > attest_body.json <<EOF
{"v":1,"tenant":"lab1","environment":"simulation","commit_id":"c1","envelope_hash":"$ENV_HASH",
 "clause_id":"delivery","predicate":"delivery.accepted","outcome":"satisfied",
 "evidence":{"object":"blob1","sha256":"$(printf '{}' | sha256sum | cut -d' ' -f1)","bytes":"2","media":"application/json"},
 "issued_ms":"$NOW","valid_until_ms":"$((NOW + 3600000))"}
EOF
S4=$($C sign --kind attestation --body-file attest_body.json --key-fd 3 \
       --key-id k4 --journal-dir journal --out sig_k4.json 3<keys/k4/secret.key | J .sig)
S5=$($C sign --kind attestation --body-file attest_body.json --key-fd 3 \
       --key-id k5 --journal-dir journal --out sig_k5.json 3<keys/k5/secret.key | J .sig)
cat > evidence.json <<EOF
{"v":1,"commit_id":"c1","envelope_hash":"$ENV_HASH","items":[
  {"clause_id":"delivery","kind":"attested","certificate":
    {"body":$(cat attest_body.json),"signatures":[{"key_id":"k4","sig":"$S4"},{"key_id":"k5","sig":"$S5"}]}}
]}
EOF
printf '{"encoding":"base64url","data":"e30"}' > blob.json
RM r_blob object put --id blob1 --kind blob --file blob.json
RM r_ev   object put --id ev1 --kind evidence --file evidence.json
RM r_sat  satisfy --id c1 --evidence-object ev1 --expected-revision 5
# → RELEASE_PENDING; release_at = now + challenge_ms (2000ms)

for i in $(seq 1 50); do
  [ "$(R _ show --id c1 | J .state)" = "SETTLED" ] && break; sleep 0.4
done
R _ show --id c1        # state SETTLED, disposition release, pay_minor 10000
```

### balances + export + verify

```bash
cat > asset.json <<'EOF'
{"code":"SIMUSD","scale":2,"custody":"sim1"}
EOF
R _ account --principal alice --asset-file asset.json      # available 90000 (100000-10000)
R _ account --principal merchant --asset-file asset.json   # available 10000

RM r_exp export --id c1 --disclosure full --out bundle     # writes bundle/ dir (must not exist)
$C verify --bundle-dir bundle --trust-file trust.json
#   → integrity:verified, authorization:verified, execution:local-simulation-verified, exit 0
$C store verify --store store --trust-file trust.json
#   → integrity:verified, projection_match:true

kill "$(cat serve.pid)"
```

## Command surface (selected)

```
commit keygen --out DIR                    Ed25519 keypair → secret.key (0600) + public.key
commit canonicalize --kind K --file F      → {kind, digest, bytes} of the canonical object
commit trust init ...                      emit an anchored trust.json (see above)
commit init --config --policy-file --trust-file --custody-manifest --out --receipt-key-file
commit serve --config                      foreground daemon on the configured unix socket
commit sign --kind K --body-file --key-fd N --key-id ID --journal-dir D --out F
commit store verify --store D --trust-file F    commit store backup --store D --out F
commit verify --bundle-dir D --trust-file F
# RPC (need --socket PATH --cap CAP; mutations also need --request-id):
health | object put|get | propose | approve | execute | satisfy | show
account | events | export | custody reconcile|retry | control apply|status
```

Every response is one JSON value; errors are
`{"ok":false,"error":{"code","message","retryable",...}}` with a nonzero exit
family — request errors (`SCHEMA_INVALID`, `INVALID_JSON`) → 2; auth/anchor
(`UNAUTHENTICATED`, `FORBIDDEN`, `NOT_FOUND`, `TRUST_UNANCHORED`) → 3;
signature/policy/evidence/quorum errors → 4; state/idempotency/object
conflicts (`STALE_REVISION`, `IDEMPOTENCY_CONFLICT`, `OBJECT_CONFLICT`) → 5;
funds (`INSUFFICIENT_FUNDS`, `BUDGET_EXCEEDED`) → 6; export/settlement
(`EXPORT_INCOMPLETE`, `SETTLEMENT_BLOCKED`, `PIN_AHEAD`) → 7; storage/clock/
busy (`STORAGE_UNAVAILABLE`, `CLOCK_UNSAFE`, `BUSY`) → 8.

## Repo layout

```
bin/commit        entry point (runs src/ under type stripping; prefers dist/)
src/cli.ts        CLI arg parsing + command dispatch (USAGE block is authoritative)
src/server.ts     unix-socket JSON-RPC + per-uid capability resolution
src/daemon.ts     startup, writer key, timer loop (auto-advance, auto-settle)
src/coordinator.ts mutation idempotency, revision checks, capability scoping
src/reducer/      commit/1 reducer methods (propose/approve/execute/satisfy/settle/…)
src/genesis.ts    store init + genesis artifact loading
src/objects.ts    object validation + canonical digests
src/proof.ts      bundle export/verify + REDUCER_DIGEST constant
src/sign.ts       offline signer (slot journal + fixture-seed refusal)
src/config.ts     commit.toml parsing (strict key sets)
src/crypto.ts     sha256, Ed25519, domain-separated digests
test/             conformance suite (fixtures.ts generates deterministic keys)
```

## License

MIT — see [LICENSE](./LICENSE).
