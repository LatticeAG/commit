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


test("CLI warning filter preserves unrelated warnings", () => {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    await import('./src/cli.ts');
    process.emitWarning('SQLite is an experimental feature and might change at any time', { type: 'ExperimentalWarning' });
    process.emitWarning('other warning', 'ExperimentalWarning');
    process.emitWarning('SQLite is an experimental feature and might change at any time', 'OtherWarning');
  `], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /ExperimentalWarning: SQLite is an experimental feature/);
  assert.match(result.stderr, /ExperimentalWarning: other warning/);
  assert.match(result.stderr, /OtherWarning: SQLite is an experimental feature/);
});

test("CLI failures remain visible on stderr", () => {
  const result = spawnSync(process.execPath, ["src/cli.ts", "init"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing required flag/);
  assert.doesNotMatch(result.stderr, /ExperimentalWarning: SQLite/);
});
