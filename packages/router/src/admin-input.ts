// Bounds at the local admin boundary and its provider probes. Error messages never quote JSON
// input: modern parser diagnostics include fragments of credentials reflected by an upstream.

const MAX_JSON_DEPTH = 64;
const MAX_JSON_VALUES = 50_000;
export const MAX_PROBE_JSON_BYTES = 2 * 1024 * 1024;
export const MAX_PROBE_ERROR_BYTES = 64 * 1024;

export function parseAdminJson(text: string): unknown {
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new Error("invalid JSON"); }
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  let visited = 0;
  while (pending.length) {
    const current = pending.pop()!;
    if (++visited > MAX_JSON_VALUES) throw new Error("JSON contains too many values");
    if (current.depth > MAX_JSON_DEPTH) throw new Error("JSON nesting exceeds the limit");
    if (current.value && typeof current.value === "object") {
      for (const child of Object.values(current.value)) pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  return value;
}

/** Bound bytes while consuming, including chunked or decompressed bodies without a useful length. */
export async function readProbeText(response: Response, limit = MAX_PROBE_ERROR_BYTES): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel().catch(() => {});
    throw new Error("probe response exceeds the size limit");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) throw new Error("probe response exceeds the size limit");
      chunks.push(value);
    }
    return Buffer.concat(chunks, bytes).toString("utf8");
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
}

export async function readProbeJson(response: Response): Promise<unknown> {
  return parseAdminJson(await readProbeText(response, MAX_PROBE_JSON_BYTES));
}
