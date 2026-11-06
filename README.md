# Commit

Commit is a simulation-profile coordinator for authorized conditional transfers, escrow, deadlines and disputes. Live initialization and certified custody are gated and are not implemented as a deployment workflow.

Requires Node.js 22.18 or newer (CI uses Node 24) and npm.

```sh
npm ci
npm run build
npm test
npm run typecheck
./bin/commit --version
```

`./bin/commit` uses the build when present and otherwise runs the TypeScript source with Node's native type stripping. `node src/cli.ts` also runs the CLI. Use `./bin/commit help --help` for command usage.

## Simulation quick start

Run these commands from the repository root. The example files contain **public, deterministic test keys** and are only for local simulation; never use them for real funds or deployment. Paths in the config are relative to the working directory. Set `uid` in `examples/simulation/commit.toml` to the result of `id -u` so the daemon can authorize your local user. Git checkouts do not preserve private file permissions, so set those before starting it:

```sh
chmod 600 examples/simulation/writer-seed.txt examples/simulation/receipt-seed.txt
./bin/commit init --config examples/simulation/commit.toml \
  --policy-file examples/simulation/policy.json \
  --trust-file examples/simulation/trust.json \
  --custody-manifest examples/simulation/custody.json \
  --receipt-key-file examples/simulation/receipt-seed.txt \
  --out examples/simulation/store --json
./bin/commit store verify --store examples/simulation/store \
  --trust-file examples/simulation/trust.json --json
./bin/commit serve --config examples/simulation/commit.toml
```

In another terminal, from the same directory:

```sh
./bin/commit health --config examples/simulation/commit.toml --cap demo --json
```

Stop the foreground daemon with Ctrl-C. Initialization is create-only; remove the example store and socket when you deliberately want to start over. The example capability permits only health checks. Provision your own keys, policy, trust pin and custody manifest for any independent environment.
