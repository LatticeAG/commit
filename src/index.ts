// commit/1 library surface.

export * as T from "./types.ts";
export { D, H, edSign, edVerify, generateKeypair, publicKeyFromSeed, privateKeyFromSeed, sha256 } from "./crypto.ts";
export { jcs, jcsBytes } from "./json/jcs.ts";
export { parseStrictJson, checkArtifactBounds } from "./json/strict.ts";
export type { Json } from "./json/strict.ts";
export { err, isCommitError, exitCodeFor, CommitError, NotImplementedSurface } from "./errors.ts";
export { Store, STORAGE_VERSION } from "./store.ts";
export { Coordinator } from "./coordinator.ts";
export { CoordinatorClock } from "./clock.ts";
export { initStore } from "./genesis.ts";
export { loadConfig } from "./config.ts";
export { startDaemon } from "./daemon.ts";
export { verifyBundle } from "./proof.ts";
export { signBody } from "./sign.ts";
export { storeVerify, storeBackup, migratePlan, migrateApply } from "./migrate.ts";
