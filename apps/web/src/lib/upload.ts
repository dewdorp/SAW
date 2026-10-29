// Resumable chunked upload (ADR-0013). Server computes SHA-256; client hash is optional (small files only).
import { api } from "./api";

export type UploadProgress = { file: string; sent: number; total: number; done: boolean; error?: string };

async function sha256(file: File): Promise<string | undefined> {
  if (file.size > 256 * 1024 * 1024 || !crypto?.subtle) return undefined;
  const h = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function uploadFiles(invId: string, kind: string, files: File[], onProgress: (p: UploadProgress[]) => void, title?: string, sourceContext?: Record<string, unknown>): Promise<{ evidenceId: string; jobId: string }> {
  const ev = await api.post(`/investigations/${invId}/evidence`, { kind, title: title || files.map((f) => f.name).slice(0, 3).join(", "), ...(sourceContext ? { source_context: sourceContext } : {}) });
  const prog: UploadProgress[] = files.map((f) => ({ file: f.name, sent: 0, total: f.size, done: false }));
  onProgress([...prog]);
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    try {
      const u = await api.post("/uploads", { evidence_id: ev.id, filename: f.name, size: f.size, sha256: await sha256(f) });
      const part = Math.min(u.part_size, 8 * 1024 * 1024);
      for (let off = 0, n = 1; off < f.size; off += part, n++) {
        let attempt = 0;
        for (;;) {
          try {
            await api.putRaw(`/uploads/${u.id}/parts/${n}`, f.slice(off, off + part));
            break;
          } catch (e) {
            if (++attempt >= 3) throw e; // resumable: same part number can be re-sent
          }
        }
        prog[i].sent = Math.min(f.size, off + part);
        onProgress([...prog]);
      }
      await api.post(`/uploads/${u.id}/complete`);
      prog[i].done = true;
    } catch (e) {
      prog[i].error = e instanceof Error ? e.message : String(e);
    }
    onProgress([...prog]);
  }
  const job = await api.post(`/evidence/${ev.id}/process`);
  return { evidenceId: ev.id, jobId: job.id };
}
