/**
 * Canary detection. A canary is a fake secret injected into the guest env.
 * If its value shows up anywhere the guest can push data out (stdout,
 * stderr, a hostname it tried to resolve, a file it wrote) the run leaked
 * a secret. We look for the raw value and the obvious encodings an
 * exfiltration script reaches for first.
 */

export interface CanaryHit {
  name: string;
  encoding: "raw" | "base64" | "base64url" | "hex" | "urlencoded" | "base32";
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 without padding. The canonical DNS-label exfil encoding: DNS is case-insensitive and base32 has no +/= that are illegal in hostnames. */
function base32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function encodings(value: string): [CanaryHit["encoding"], string][] {
  const buf = Buffer.from(value, "utf8");
  return [
    ["raw", value],
    ["base64", buf.toString("base64")],
    ["base64url", buf.toString("base64url")],
    ["hex", buf.toString("hex")],
    ["urlencoded", encodeURIComponent(value)],
    ["base32", base32(buf)],
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
