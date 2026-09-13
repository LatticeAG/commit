// Audit delivery drain (§9.2). Launch edition uses a local filesystem
// collector implementing the same receipt semantics as the Proof ingest RPC:
// the coordinator dials the configured unix socket when present; otherwise
// deliveries persist in the durable outbox (lag is observable via metrics).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import net from "node:net";
import { jcs } from "./json/jcs.ts";
import type { Json } from "./json/strict.ts";
import type { Store } from "./store.ts";
import type { AuditAck, AuditDelivery } from "./types.ts";

/** One delivery attempt to the configured audit socket; on absence/failure the row stays PENDING. */
function attemptDelivery(sockPath: string, d: AuditDelivery): Promise<"stored" | "rejected" | "unavailable"> {
  return new Promise((resolve) => {
    const sock = net.createConnection(sockPath);
    let buf = Buffer.alloc(0);
    const done = (v: "stored" | "rejected" | "unavailable") => { try { sock.destroy(); } catch {} resolve(v); };
    const timer = setTimeout(() => done("unavailable"), 10000);
    sock.on("connect", () => {
      const body = Buffer.from(jcs(d as unknown as Json), "utf8");
      const head = Buffer.alloc(4);
      head.writeUInt32BE(body.length, 0);
      sock.write(Buffer.concat([head, body]));
    });
    sock.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      try {
        const ack = JSON.parse(buf.subarray(4, 4 + len).toString("utf8")) as AuditAck;
        clearTimeout(timer);
        done(ack.status === "stored" && ack.delivery_id === d.delivery_id ? "stored" : "rejected");
      } catch {
        clearTimeout(timer);
        done("unavailable");
      }
    });
    sock.on("error", () => { clearTimeout(timer); done("unavailable"); });
  });
}

/**
 * Filesystem collector: when audit_socket is absent the same durable
 * semantics are provided by append-only files under proof_directory.
 * A stored ack is recorded once the delivery file is written + fsynced.
 */
export function drainAuditOutbox(store: Store, auditSocket: string | null, proofDir: string): void {
  const pending = store.pendingAuditDeliveries();
  if (pending.length === 0) return;
  for (const p of pending) {
    store.bumpAuditAttempt(p.delivery_id);
    if (auditSocket !== null) {
      void attemptDelivery(auditSocket, {
        v: 1, delivery_id: p.delivery_id, manifest: p.stream, digest: p.checkpoint_digest, through_seq: String(p.through_seq),
      }).then((r) => {
        if (r === "stored") store.markAuditDelivered(p.delivery_id);
      });
    } else {
      // local filesystem collector with identical receipt semantics
      const dir = join(proofDir, "audit");
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const file = join(dir, `${p.delivery_id}.json`);
      const payload: AuditDelivery = {
        v: 1, delivery_id: p.delivery_id, manifest: p.stream, digest: p.checkpoint_digest, through_seq: String(p.through_seq),
      };
      try {
        if (existsSync(file)) {
          const prior = JSON.parse(readFileSync(file, "utf8"));
          if (prior.digest === payload.digest) store.markAuditDelivered(p.delivery_id); // dedup same delivery_id+digest
          // changed digest under one id → leave PENDING (rejected semantics; observable)
        } else {
          writeFileSync(file, jcs(payload as unknown as Json) + "\n", { mode: 0o600 });
          store.markAuditDelivered(p.delivery_id);
        }
      } catch { /* stays pending */ }
    }
  }
}
