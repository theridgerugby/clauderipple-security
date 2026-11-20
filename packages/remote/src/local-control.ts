// Host-local authenticated TLS boundary. Relay peers enter HostServer.connected(), never here.
import type http from "node:http";
import https from "node:https";
import { TLSSocket } from "node:tls";
import type { Duplex } from "node:stream";
import { randomBytes } from "node:crypto";
import qrcode from "qrcode-generator";
import { DEFAULT_RELAY, DIRECT_PHONE_DISABLED, PHONE_REPAIR_REQUIRED, loadConfig, normalizeRelay, relayPairingUrl, resolveBind, saveConfig } from "./config.ts";
import { rotatePhonePairingToken } from "./phone-auth-migration.ts";
import type { HostConfig } from "./config.ts";
import type { ModInbox } from "./mod-inbox.ts";
import type { ApprovalAnswer } from "./mod-approval.ts";
import { settingsId, validSettingsJobAction, type SettingsJobs } from "./settings-jobs.ts";
import { ADMIN_TOKEN_HEADER, ensureAdminToken, validAdminToken } from "../../router/src/admin-auth.ts";
import { ensureAdminTlsIdentity, writeAdminEndpoint } from "../../router/src/admin-transport-state.ts";
import { localControlHome } from "./local-transport.ts";

export interface Phone { clientId: string; connected: boolean; lastSeen: number | null; push: boolean }
export interface LocalControlOptions {
  dir: string;
  config: HostConfig;
  version: string;
  hostPublicKey: string;
  phones(): Phone[];
  rotate(token: string): void;
  shutdown?(): void;
  /** A turn is in progress: an update restarts the host only when this is false. */
  busy?(): boolean;
  prepareRefresh?(): boolean;
  refresh?(): void;
  inbox?: ModInbox;
  settingsJobs?: SettingsJobs;
  /** The Claude app sessions' mod: its approvals (classic.PermissionRequest) and its own /clear moves. */
  mod?: ModHost;
}

/** What the mod reports about its own permission asks and /clear runs (see Sessions). */
export interface ModHost {
  modApprovalStart(req: { askId: string; session: string; tool: string; input: Record<string, unknown>; suggestions: unknown[]; title: string }): Promise<{ state: "hold" | "local" }>;
  /** `sentAt` is when the hook sent the poll (its clock, this host's): the poll is dated by it, never by a later arrival. */
  modApprovalPoll(askId: string, waitMs?: number, sentAt?: number): Promise<unknown>;
  /** The hook is done with its ask. An ask the phone answered first comes back with its answer (the hook applies it). */
  modApprovalDone(askId: string): { answer?: ApprovalAnswer };
  reportMoved(itemId: string, from: string, to: string): boolean;
}

/** A mod's approval request carries the tool's whole input (a Write's content): larger than the settings cap. */
const MOD_BODY_CAP = 512 * 1024;

export function isLoopback(address: string | undefined): boolean {
  return address === "::1" || /^127(?:\.\d{1,3}){3}$/.test(address ?? "") || /^::ffff:127(?:\.\d{1,3}){3}$/i.test(address ?? "");
}

/** Compatibility name for callers: this creates only the new owner-protected TLS capability. */
export function localSecret(dir: string): string {
  return ensureAdminToken(localControlHome(dir));
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  // No response leaves an unread request body occupying a keep-alive socket. This also covers
  // authenticated method/route errors and no-body actions such as shutdown, not just auth denial.
  const socket = res.socket;
  res.once("finish", () => socket?.destroySoon());
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", connection: "close" });
  res.end(JSON.stringify(body));
}

async function settingsBody(req: http.IncomingMessage, cap = 4096): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  // An oversized body is read to its end (up to 8 caps) before refusing, so the caller's 400 reaches
  // the client instead of a reset socket still being written to.
  for await (const chunk of req) {
    size += Buffer.byteLength(chunk);
    if (size > cap * 8) throw new Error(`settings body exceeds ${cap} bytes`);
    if (size <= cap) chunks.push(Buffer.from(chunk));
  }
  if (size > cap) throw new Error(`settings body exceeds ${cap} bytes`);
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

const ASK_ID = /^[\w-]{1,100}$/;
/** A poll's send time: the hook's clock in whole milliseconds since the epoch. */
const SENT_AT = /^\d{1,15}$/;
/** The one request body a mod sends for an approval; anything else is refused, never guessed at. */
function approvalStart(raw: unknown): { askId: string; session: string; tool: string; input: Record<string, unknown>; suggestions: unknown[]; title: string } | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const body = raw as Record<string, unknown>;
  const { askId, session, tool, input, suggestions, title } = body;
  if (typeof askId !== "string" || !ASK_ID.test(askId)) return null;
  if (typeof session !== "string" || !session || session.length > 200) return null;
  if (typeof tool !== "string" || !tool || tool.length > 100) return null;
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (!Array.isArray(suggestions) || suggestions.length > 16) return null;
  if (title !== undefined && (typeof title !== "string" || title.length > 500)) return null;
  return { askId, session, tool, input: input as Record<string, unknown>, suggestions, title: typeof title === "string" ? title : "" };
}

export class LocalControl {
  private secret: string;
  private running: HostConfig;
  private where: ReturnType<typeof resolveBind>;
  private opts: LocalControlOptions;
  private server: https.Server | null = null;
  private tlsPort: number | null = null;
  private readonly sockets = new Set<Duplex>();
  private readonly instanceId = randomBytes(16).toString("hex");
  constructor(opts: LocalControlOptions) {
    this.opts = opts;
    this.secret = localSecret(opts.dir);
    this.running = { ...opts.config };
    this.where = resolveBind(this.running.bind);
  }

  /** Only a successfully bound public host may publish its independent TLS control endpoint. */
  async listen(publicPort: number): Promise<void> {
    if (this.server || !Number.isSafeInteger(publicPort) || publicPort < 1 || publicPort > 65_535) throw new Error("invalid local control start");
    // The listener owner may have atomically migrated phone pairing state after construction.
    this.running = { ...this.opts.config };
    this.where = resolveBind(this.running.bind);
    const home = localControlHome(this.opts.dir);
    const identity = ensureAdminTlsIdentity(home);
    const server = https.createServer({ cert: identity.certPem, key: identity.keyPem, minVersion: "TLSv1.2", handshakeTimeout: 5000, maxHeaderSize: 16 * 1024, connectionsCheckingInterval: 1000 }, (req, res) => {
      void this.handle(req, res).catch(() => { if (!res.headersSent) json(res, 500, { error: "host local control failed" }); else res.destroy(); });
    });
    server.headersTimeout = 10_000;
    server.requestTimeout = 15_000;
    server.keepAliveTimeout = 1000;
    server.maxConnections = 128;
    server.on("connection", socket => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
    });
    this.server = server;
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
      });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("local control did not bind");
      this.tlsPort = address.port;
      this.running.port = publicPort;
      this.opts.config.port = publicPort;
      writeAdminEndpoint(home, { version: 1, instanceId: this.instanceId, publicPort, tlsPort: address.port });
    } catch (error) { await this.close(); throw error; }
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = null;
    this.tlsPort = null;
    if (server) {
      await new Promise<void>(resolve => {
        // A peer stalled before TLS/HTTP headers or in a body must not hold host shutdown open.
        const deadline = setTimeout(() => {
          server.closeAllConnections();
          for (const socket of this.sockets) socket.destroy();
        }, 250);
        deadline.unref();
        server.close(() => { clearTimeout(deadline); resolve(); });
        server.closeIdleConnections();
      });
      // Retain the last protected discovery record. A second shutdown (the Windows install
      // flow checks twice) can distinguish ECONNREFUSED from missing authenticated state.
      // A different process taking this port still has to prove the exact pinned TLS identity.
      // Failed startup also leaves any preceding instance's discovery untouched.
    }
  }

  /** No caller-supplied error text is logged or reflected: pairing credentials stay out of logs. */
  async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const critical = new Set(["host", "origin", ADMIN_TOKEN_HEADER, "x-clauderipple-instance-id"]);
    const seen = new Set<string>();
    let duplicate = false;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i]!.toLowerCase();
      if (critical.has(name)) { if (seen.has(name)) duplicate = true; seen.add(name); }
    }
    if (!(req.socket instanceof TLSSocket) || !req.socket.encrypted || !isLoopback(req.socket.remoteAddress) || duplicate ||
        req.headers.host !== `127.0.0.1:${this.tlsPort}` || req.headers.origin !== undefined ||
        req.headers["sec-fetch-site"] !== undefined ||
        req.headers["x-clauderipple-instance-id"] !== this.instanceId ||
        !validAdminToken(req.headers[ADMIN_TOKEN_HEADER], this.secret)) {
      json(res, 403, { error: "local control authentication required" });
      return;
    }
    const url = new URL(req.url ?? "/", "https://local");
    if (!url.pathname.startsWith("/api/local/")) { json(res, 404, { error: "unknown local control endpoint" }); return; }
    const route = url.pathname.slice(4);
    try {
      if (route === "/local/settings-jobs" && req.method === "GET" && this.opts.settingsJobs) {
        const exclude = url.searchParams.get("exclude");
        if (!settingsId(exclude) || url.searchParams.getAll("exclude").length !== 1) { json(res, 400, { error: "invalid helper" }); return; }
        json(res, 200, { jobs: this.opts.settingsJobs.pending(exclude) }); return;
      }
      if ((route === "/local/settings-jobs/claim" || route === "/local/settings-jobs/result") && req.method === "POST" && this.opts.settingsJobs) {
        let raw: unknown;
        try { raw = await settingsBody(req); } catch { json(res, 400, { error: "invalid settings job request" }); return; }
        const result = route.endsWith("/result");
        if (!validSettingsJobAction(raw, result)) { json(res, 400, { error: "invalid settings job request" }); return; }
        const ok = "outcome" in raw ? this.opts.settingsJobs.result(raw.jobId, raw.outcome, raw.detail) : this.opts.settingsJobs.claim(raw.jobId, raw.helper);
        json(res, ok ? 200 : 409, ok ? { ok: true } : { error: "job unavailable" }); return;
      }
      if (route === "/local/inbox" && req.method === "GET" && this.opts.inbox) {
        const session = url.searchParams.get("session");
        if (!session || session.length > 200 || url.searchParams.getAll("session").length !== 1) { json(res, 400, { error: "invalid session" }); return; }
        // Every poll is the mod's heartbeat: the host offers clear-in-place and abort only to a mod that reads.
        this.opts.inbox.listen(session, Date.now());
        json(res, 200, { offers: this.opts.inbox.pending(session) });
        return;
      }
      if (route.startsWith("/local/mod/") && this.opts.mod) {
        const mod = this.opts.mod;
        if (route === "/local/mod/approval" && req.method === "POST") {
          let raw: unknown;
          try { raw = await settingsBody(req, MOD_BODY_CAP); } catch { json(res, 400, { error: "invalid approval request" }); return; }
          const start = approvalStart(raw);
          if (!start) { json(res, 400, { error: "invalid approval request" }); return; }
          json(res, 200, await mod.modApprovalStart(start)); return;
        }
        if (route === "/local/mod/approval" && req.method === "GET") {
          const askId = url.searchParams.get("askId");
          if (!askId || !ASK_ID.test(askId) || url.searchParams.getAll("askId").length !== 1) { json(res, 400, { error: "invalid approval" }); return; }
          // The send time is optional: a mod that predates it is dated by the poll's arrival, as before.
          const sent = url.searchParams.getAll("sentAt");
          if (sent.length > 1 || sent.length === 1 && !SENT_AT.test(sent[0]!)) { json(res, 400, { error: "invalid approval" }); return; }
          json(res, 200, await mod.modApprovalPoll(askId, undefined, sent.length ? Number(sent[0]) : undefined)); return;
        }
        if (route === "/local/mod/approval/done" && req.method === "POST") {
          let raw: unknown;
          try { raw = await settingsBody(req); } catch { json(res, 400, { error: "invalid approval" }); return; }
          const askId = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>).askId : undefined;
          if (typeof askId !== "string" || !ASK_ID.test(askId)) { json(res, 400, { error: "invalid approval" }); return; }
          const done = mod.modApprovalDone(askId);
          json(res, 200, done.answer ? { ok: true, state: "answered", answer: done.answer } : { ok: true }); return;
        }
        if (route === "/local/mod/moved" && req.method === "POST") {
          let raw: unknown;
          try { raw = await settingsBody(req); } catch { json(res, 400, { error: "invalid move" }); return; }
          const body = raw && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : null;
          if (!body || typeof body.itemId !== "string" || !ASK_ID.test(body.itemId) || typeof body.from !== "string" || typeof body.to !== "string") { json(res, 400, { error: "invalid move" }); return; }
          const ok = mod.reportMoved(body.itemId, body.from, body.to);
          json(res, ok ? 200 : 409, ok ? { ok: true } : { error: "move unavailable" }); return;
        }
      }
      if ((route === "/local/inbox/claim" || route === "/local/inbox/result") && req.method === "POST" && this.opts.inbox) {
        let raw: unknown;
        try { raw = await settingsBody(req); } catch { json(res, 400, { error: "invalid inbox request" }); return; }
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) { json(res, 400, { error: "invalid inbox request" }); return; }
        const body = raw as Record<string, unknown>;
        const result = route.endsWith("/result");
        if (typeof body.itemId !== "string" || !/^[\w-]{1,100}$/.test(body.itemId) || Object.keys(body).some(key => key !== "itemId" && (!result || key !== "outcome")) || result && body.outcome !== "submitted" && body.outcome !== "failed") {
          json(res, 400, { error: "invalid inbox request" }); return;
        }
        const ok = result ? this.opts.inbox.result(body.itemId, body.outcome as "submitted" | "failed") : this.opts.inbox.claim(body.itemId);
        json(res, ok ? 200 : 409, ok ? { ok: true } : { error: "offer unavailable" });
        return;
      }
      if (route === "/local/status" && req.method === "GET") {
        const cfg = this.running;
        const saved = loadConfig(this.opts.dir, false);
        json(res, 200, {
          version: this.opts.version, mode: cfg.relay ? "relay" : "local-only",
          ...(cfg.relay ? { relay: cfg.relay } : {}), bind: cfg.bind, port: cfg.port,
          reachableFromPhone: !!cfg.relay, pushReady: !!cfg.relay,
          ...(!cfg.relay ? { phoneConnectionNotice: DIRECT_PHONE_DISABLED } : {}),
          phones: this.opts.phones(), settings: { bind: saved.bind, ...(saved.relay ? { relay: saved.relay } : {}) }, defaultRelay: DEFAULT_RELAY,
          restartRequired: saved.bind !== cfg.bind || saved.relay !== cfg.relay,
          busy: this.opts.busy?.() ?? false,
        });
        return;
      }
      if (route === "/local/refresh" && req.method === "POST" && this.opts.prepareRefresh && this.opts.refresh) {
        if (!this.opts.prepareRefresh()) { json(res, 409, { error: "host busy" }); return; }
        res.once("finish", () => this.opts.refresh?.());
        json(res, 200, { ok: true });
        return;
      }
      if (route === "/local/shutdown" && req.method === "POST" && this.opts.shutdown) {
        res.once("finish", () => this.opts.shutdown?.());
        json(res, 200, { ok: true });
        return;
      }
      if (route === "/local/pairing" && req.method === "GET") {
        const cfg = this.running;
        if (!cfg.relay) { json(res, 409, { error: DIRECT_PHONE_DISABLED }); return; }
        if (cfg.pairingSecurityVersion !== 2) { json(res, 409, { error: PHONE_REPAIR_REQUIRED }); return; }
        const url = relayPairingUrl(cfg.relay, cfg.serverId, this.opts.hostPublicKey, this.opts.config.token);
        const qr = qrcode(0, "M");
        qr.addData(url);
        qr.make();
        json(res, 200, { url, svg: qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true }) });
        return;
      }
      if (route === "/local/settings" && req.method === "POST") {
        let next: HostConfig;
        try { next = this.settings(await settingsBody(req)); }
        catch { json(res, 400, { error: "invalid settings: use an HTTPS Relay URL (or off) and bind local, lan or tailscale; the selected network must be available" }); return; }
        saveConfig(next, this.opts.dir);
        json(res, 200, { restartRequired: next.bind !== this.running.bind || next.relay !== this.running.relay });
        return;
      }
      if (route === "/local/rotate" && req.method === "POST") {
        const rotated = rotatePhonePairingToken(this.opts.dir, this.opts.config.token);
        this.opts.config.token = rotated.token;
        this.opts.config.pairingSecurityVersion = rotated.pairingSecurityVersion;
        this.running.pairingSecurityVersion = rotated.pairingSecurityVersion;
        this.opts.rotate(rotated.token);
        json(res, 200, { ok: true });
        return;
      }
      json(res, 404, { error: "unknown local control endpoint or method" });
    } catch {
      json(res, 500, { error: "host local control failed" });
    }
  }

  private settings(raw: unknown): HostConfig {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("expected object");
    const body = raw as Record<string, unknown>;
    if (Object.keys(body).some(key => key !== "relay" && key !== "bind")) throw new Error("unknown setting");
    const cfg = loadConfig(this.opts.dir, false);
    if (body.relay !== undefined) {
      if (typeof body.relay !== "string") throw new Error("invalid relay");
      if (body.relay === "off") delete cfg.relay;
      else cfg.relay = normalizeRelay(body.relay);
    }
    if (body.bind !== undefined) {
      if (body.bind !== "local" && body.bind !== "lan" && body.bind !== "tailscale") throw new Error("invalid bind");
      cfg.bind = body.bind === "local" ? "127.0.0.1" : body.bind;
      resolveBind(cfg.bind);
    }
    return cfg;
  }
}
