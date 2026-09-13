/**
 * Canary detection. A canary is a fake secret injected into the guest env.
 * If its value shows up anywhere the guest can push data out (stdout,
 * stderr, a hostname it tried to resolve, a file it wrote) the run leaked
 * a secret. We look for the raw value and the obvious encodings an
 * exfiltration script reaches for first.
 */

export interface CanaryHit {
  name: string;
  encoding: "raw" | "base64" | "base64url" | "hex" | "urlencoded";
}

function encodings(value: string): [CanaryHit["encoding"], string][] {
  const buf = Buffer.from(value, "utf8");
  return [
    ["raw", value],
    ["base64", buf.toString("base64")],
    ["base64url", buf.toString("base64url")],
    ["hex", buf.toString("hex")],
    ["urlencoded", encodeURIComponent(value)],
  ];
}

/** Find canaries in a blob of text. Short prefixes count for hostnames (DNS exfil chunks). */
export function findCanaries(text: string, canaries: Record<string, string>, opts: { minChunk?: number } = {}): CanaryHit[] {
  if (!text) return [];
  const hits: CanaryHit[] = [];
  const lower = text.toLowerCase();
  const minChunk = opts.minChunk ?? 0;
  for (const [name, value] of Object.entries(canaries)) {
    for (const [encoding, needle] of encodings(value)) {
      if (needle.length && lower.includes(needle.toLowerCase())) {
        hits.push({ name, encoding });
        break;
      }
      if (minChunk > 0 && needle.length > minChunk) {
        // DNS exfil splits the secret into label-sized chunks. Match any
        // chunk of the encoded value at least `minChunk` long.
        for (let i = 0; i + minChunk <= needle.length; i += Math.max(1, Math.floor(minChunk / 2))) {
          const chunk = needle.slice(i, i + minChunk).toLowerCase();
          if (lower.includes(chunk)) {
            hits.push({ name, encoding });
            i = needle.length;
            break;
          }
        }
        if (hits.some((h) => h.name === name)) break;
      }
    }
  }
  return hits;
}
