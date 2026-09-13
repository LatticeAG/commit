// Unix-socket RPC server: 4-byte BE length + one UTF-8 JSON frame per
// direction. Peer credentials are resolved via socket inode -> ss -> /proc
// (the portable SO_PEERCRED equivalent available in this environment).

import net from "node:net";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { err } from "./errors.ts";
import { jcs } from "./json/jcs.ts";
import { parseStrictJson, type Json } from "./json/strict.ts";
import type { Coordinator } from "./coordinator.ts";
import type { Capability } from "./types.ts";

/** Map a connected socket fd to the peer process uid. */
export function peerUid(fd: number): number | null {
  try {
    const link = readlinkSync(`/proc/self/fd/${fd}`);
    const m = /socket:\[(\d+)\]/.exec(link);
    if (!m) return null;
    const inode = m[1]!;
    const out = execFileSync("ss", ["-xn"], { encoding: "utf8", timeout: 5000 });
    let peerInode: string | null = null;
    // ss unix rows carry socket inodes either as `path:INODE`/`*:INODE` or as a
    // bare numeric column after the address — collect both forms per line.
    for (const line of out.split("\n")) {
      const fields = line.trim().split(/\s+/).slice(4); // skip Netid/State/Recv-Q/Send-Q
      const inodes = fields
        .map((f) => /:(\d+)$/.exec(f)?.[1] ?? (/^\d{4,}$/.test(f) ? f : null))
        .filter((x): x is string => x !== null);
      if (!inodes.includes(inode)) continue;
      const other = inodes.find((x) => x !== inode);
      if (other !== undefined) { peerInode = other; break; }
    }
    if (peerInode === null) return null;
    for (const pid of readdirSync("/proc").filter((x) => /^\d+$/.test(x))) {
      const fdDir = `/proc/${pid}/fd`;
      let names: string[];
      try { names = readdirSync(fdDir); } catch { continue; }
      for (const f of names) {
        try {
          if (readlinkSync(`${fdDir}/${f}`) === `socket:[${peerInode}]`) {
            const status = readFileSync(`/proc/${pid}/status`, "utf8");
            const um = /^Uid:\s+(\d+)/m.exec(status);
            return um?.[1] !== undefined ? parseInt(um[1], 10) : null;
          }
        } catch { /* fd vanished */ }
      }
    }
    return null;
  } catch {
    return null;
  }
}

export interface CallOptions { timeoutMs?: number; maxFrameBytes?: number }

interface FrameConn {
  socket: net.Socket;
  buf: Buffer;
  busy: boolean;
}

export function serve(
  sockPath: string,
  coordinator: Coordinator,
  capsByUid: Map<number, Capability>,
  opts: { maxFrameBytes: number; maxInflight: number },
): net.Server {
  if (existsSync(sockPath)) rmSync(sockPath);
  mkdirSync(dirname(sockPath), { recursive: true });
  let inflight = 0;

  const server = net.createServer((socket) => {
    const conn: FrameConn = { socket, buf: Buffer.alloc(0), busy: false };
    let uid: number | null = null;
    // resolve peer uid lazily on first frame so ss sees the connected pair
    const ensureUid = (): number | null => {
      if (uid !== null) return uid;
      const fd = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
      if (fd === undefined) return null;
      uid = peerUid(fd);
      return uid;
    };

    socket.on("data", (chunk) => {
      conn.buf = Buffer.concat([conn.buf, chunk]);
      drain(conn, coordinator, capsByUid, opts, ensureUid, () => inflight, (n) => { inflight += n; });
    });
    socket.on("error", () => socket.destroy());
  });
  server.listen(sockPath);
  server.on("listening", () => {
    try { statSync(sockPath); } catch { /* */ }
  });
  return server;
}

function drain(
  conn: FrameConn,
  coordinator: Coordinator,
  capsByUid: Map<number, Capability>,
  opts: { maxFrameBytes: number; maxInflight: number },
  ensureUid: () => number | null,
  getInflight: () => number,
  addInflight: (n: number) => void,
): void {
  if (conn.busy) return;
  while (conn.buf.length >= 4) {
    const len = conn.buf.readUInt32BE(0);
    if (len === 0 || len > opts.maxFrameBytes) {
      sendError(conn.socket, { code: "LIMIT_EXCEEDED", retryable: false, message: "frame length invalid", current_revision: null });
      conn.socket.destroy();
      return;
    }
    if (conn.buf.length < 4 + len) return;
    const frame = conn.buf.subarray(4, 4 + len);
    conn.buf = conn.buf.subarray(4 + len);
    conn.busy = true;
    void handle(conn, frame, coordinator, capsByUid, getInflight, addInflight, ensureUid)
      .finally(() => { conn.busy = false; drain(conn, coordinator, capsByUid, opts, ensureUid, getInflight, addInflight); });
    return;
  }
}

async function handle(
  conn: FrameConn,
  frame: Buffer,
  coordinator: Coordinator,
  capsByUid: Map<number, Capability>,
  getInflight: () => number,
  addInflight: (n: number) => void,
  ensureUid: () => number | null,
): Promise<void> {
  let request: Json;
  try {
    request = parseStrictJson(frame);
  } catch {
    sendError(conn.socket, { code: "INVALID_JSON", retryable: false, message: "request frame is not strict JSON", current_revision: null });
    return;
  }
  if (getInflight() >= 1000) {
    sendError(conn.socket, { code: "LIMIT_EXCEEDED", retryable: true, message: "too many inflight requests", current_revision: null });
    return;
  }
  addInflight(1);
  try {
    const uid = ensureUid();
    if (uid === null) {
      sendError(conn.socket, { code: "UNAUTHENTICATED", retryable: false, message: "peer credentials unavailable", current_revision: null });
      return;
    }
    const cap = capsByUid.get(uid);
    if (!cap) {
      sendError(conn.socket, { code: "UNAUTHENTICATED", retryable: false, message: "no principal for peer uid", current_revision: null });
      return;
    }
    const reqId = typeof request === "object" && request !== null && typeof (request as { request_id?: unknown }).request_id === "string"
      ? (request as { request_id: string }).request_id : "req_bad";
    const res = await coordinator.call(cap.principal, cap, request);
    sendJson(conn.socket, { v: 1, request_id: reqId, ...res });
  } finally {
    addInflight(-1);
  }
}

function sendJson(socket: net.Socket, v: unknown): void {
  const body = Buffer.from(jcs(v as Json), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  socket.write(Buffer.concat([head, body]));
}

function sendError(socket: net.Socket, error: { code: string; retryable: boolean; message: string; current_revision: string | null }): void {
  sendJson(socket, { ok: false, error });
}

/** Client: one request → one canonical JSON response. */
export async function rpcCall(
  sockPath: string,
  request: unknown,
  opts: CallOptions = {},
): Promise<{ ok: true; result: unknown } | { ok: false; error: { code: string; retryable: boolean; message: string; current_revision: string | null } }> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(sockPath);
    const max = opts.maxFrameBytes ?? 4 * 1024 * 1024;
    const timeoutMs = opts.timeoutMs ?? 30000;
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(err("INTERNAL", "request timed out")); }, timeoutMs);
    socket.on("connect", () => {
      const body = Buffer.from(jcs(request as Json), "utf8");
      const head = Buffer.alloc(4);
      head.writeUInt32BE(body.length, 0);
      socket.write(Buffer.concat([head, body]));
    });
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (len === 0 || len > max) { clearTimeout(timer); socket.destroy(); reject(err("INTERNAL", "bad response frame")); return; }
      if (buf.length < 4 + len) return;
      const body = buf.subarray(4, 4 + len);
      clearTimeout(timer);
      socket.destroy();
      try {
        resolve(JSON.parse(body.toString("utf8")));
      } catch {
        reject(err("INTERNAL", "response is not JSON"));
      }
    });
    socket.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}
