/**
 * Snapshot and diff the guest workspace through `sandbox.fs`.
 *
 * The SDK's filesystem API is rooted at /workspace (it reports "/" and "."
 * as the same directory), so this diff sees everything the guest wrote to
 * its workspace and nothing outside it. Contents are hashed for files up to
 * a size cap so "modify" is real, not a guess from size.
 */
import { createHash } from "node:crypto";
import type { FsChange } from "@firewall/contract";

export interface SandboxFsLike {
  readDir(path: string): Promise<readonly { name: string; kind: "file" | "directory"; size: number }[]>;
  readFile(path: string): Promise<Uint8Array>;
}

export interface FsEntry {
  kind: "file" | "directory";
  size: number;
  hash?: string;
}

export type FsSnapshot = Map<string, FsEntry>;

const HASH_CAP_BYTES = 1024 * 1024;

export async function snapshot(fs: SandboxFsLike, root = "/"): Promise<FsSnapshot> {
  const out: FsSnapshot = new Map();
  await walk(fs, root === "/" ? "" : root.replace(/\/$/, ""), out);
  return out;
}

async function walk(fs: SandboxFsLike, dir: string, out: FsSnapshot): Promise<void> {
  let entries: Awaited<ReturnType<SandboxFsLike["readDir"]>>;
  try {
    entries = await fs.readDir(dir === "" ? "/" : dir);
  } catch {
    return;
  }
  for (const e of entries) {
    const rel = dir === "" ? e.name : `${dir}/${e.name}`;
    const abs = `/workspace/${rel}`;
    if (e.kind === "directory") {
      out.set(abs, { kind: "directory", size: 0 });
      await walk(fs, rel, out);
    } else {
      let hash: string | undefined;
      if (e.size <= HASH_CAP_BYTES) {
        try {
          hash = createHash("sha1").update(await fs.readFile(rel)).digest("hex");
        } catch {
          hash = undefined;
        }
      }
      out.set(abs, { kind: "file", size: e.size, hash });
    }
  }
}

export function diff(
  before: FsSnapshot,
  after: FsSnapshot,
  isWritable: (absPath: string) => boolean,
): FsChange[] {
  const changes: FsChange[] = [];
  for (const [path, entry] of after) {
    const prev = before.get(path);
    if (!prev) {
      if (entry.kind === "directory") continue;
      changes.push({ path, op: "create", bytes: entry.size, allowed: isWritable(path) });
    } else if (entry.kind === "file" && (prev.size !== entry.size || (prev.hash && entry.hash && prev.hash !== entry.hash))) {
      changes.push({ path, op: "modify", bytes: entry.size, allowed: isWritable(path) });
    }
  }
  for (const [path, entry] of before) {
    if (!after.has(path) && entry.kind === "file") {
      changes.push({ path, op: "delete", allowed: isWritable(path) });
    }
  }
  return changes;
}
