// Append-only log file with size-based rotation. Never logs request bodies or headers.

import fs from "node:fs";
import { openPrivateAppend } from "./private-file.ts";
import { redactErrorText } from "./redact.ts";

export class Logger {
  private fd: number | null = null;
  private bytes = 0;
  private writesSinceCheck = 0;
  private readonly file: string | null;
  private readonly maxBytes: number;
  private readonly keep: number;
  private readonly echo: boolean;
  private readonly memoryOnly: boolean;
  private readonly recent: string[] = [];

  constructor(file: string | null, maxBytes: number, keep: number, echo: boolean, memoryOnly = false) {
    this.memoryOnly = memoryOnly;
    this.file = memoryOnly ? null : file;
    this.maxBytes = maxBytes;
    this.keep = keep;
    this.echo = !memoryOnly && echo;
    if (this.file) {
      this.open();
    }
  }

  private open(): void {
    if (!this.file) return;
    this.fd = openPrivateAppend(this.file);
    try {
      this.bytes = fs.fstatSync(this.fd).size;
    } catch {
      this.bytes = 0;
    }
  }

  private rotate(): void {
    if (!this.file || this.fd === null) return;
    fs.closeSync(this.fd);
    this.fd = null;
    for (let i = this.keep - 1; i >= 1; i--) {
      const from = `${this.file}.${i}`;
      const to = `${this.file}.${i + 1}`;
      if (fs.existsSync(from)) fs.renameSync(from, to);
    }
    if (this.keep >= 1) fs.renameSync(this.file, `${this.file}.1`);
    else fs.unlinkSync(this.file);
    this.open();
  }

  line(level: "info" | "warn" | "error", msg: string): void {
    const d = new Date();
    const p = (n: number): string => String(n).padStart(2, "0");
    const ts = `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; // local time, like the app's own logs
    const safeMessage = redactErrorText(msg.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u0085\u2028\u2029]/g, " "), [], 16 * 1024);
    const out = `${ts} ${level === "info" ? "" : level.toUpperCase() + " "}${safeMessage}\n`;
    if (this.memoryOnly) {
      this.recent.push(out);
      if (this.recent.length > 500) this.recent.shift();
      return;
    }
    if (this.echo || this.fd === null) process.stdout.write(out);
    if (this.fd !== null) {
      try {
        fs.writeSync(this.fd, out);
        this.bytes += Buffer.byteLength(out);
        if (++this.writesSinceCheck >= 50) {
          this.writesSinceCheck = 0;
          if (this.bytes >= this.maxBytes) this.rotate();
        }
      } catch {
        /* logging must never take the router down */
      }
    }
  }

  info(msg: string): void {
    this.line("info", msg);
  }
  warn(msg: string): void {
    this.line("warn", msg);
  }
  error(msg: string): void {
    this.line("error", msg);
  }

  /** Personal mode never persists or echoes potentially sensitive provider error diagnostics. */
  memoryTail(n: number): string | null {
    const count = Number.isFinite(n) ? Math.max(0, Math.min(500, Math.floor(n))) : 0;
    return this.memoryOnly ? (count === 0 ? "" : this.recent.slice(-count).join("")) : null;
  }

  close(): void {
    if (this.fd === null) return;
    fs.closeSync(this.fd);
    this.fd = null;
  }
}
