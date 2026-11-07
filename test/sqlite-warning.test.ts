import { spawnSync } from "node:child_process";
import { strict as assert } from "node:assert";
import { test } from "node:test";

test("loading SQLite suppresses its warning without suppressing other warnings", () => {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    await import('./src/store.ts');
    process.emitWarning('other warning', 'ExperimentalWarning');
  `], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /SQLite is an experimental feature/);
  assert.match(result.stderr, /ExperimentalWarning: other warning/);
});

test("CLI version has no SQLite warning", () => {
  const result = spawnSync(process.execPath, ["src/cli.ts", "--version"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "commit 1.0.0\n");
  assert.equal(result.stderr, "");
});
