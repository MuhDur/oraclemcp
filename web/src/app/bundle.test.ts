import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// B4.6 no-external-request contract (iec3.2.26). The operator console must work
// fully offline / air-gapped: the built bundle may not reach out to Google Fonts
// or any CDN at runtime. This scans the produced dist for known external hosts
// and for external font/script/style URLs. Requires `npm run build` first.

const DIST = resolve(process.cwd(), "dist");

// Text asset extensions worth scanning; binaries (woff2, png, ico) are skipped.
const TEXT_EXT = new Set([".js", ".css", ".html", ".json", ".map", ".svg", ".txt"]);

const FORBIDDEN_HOSTS = [
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "www.gstatic.com",
  "ajax.googleapis.com",
  "cdnjs.cloudflare.com",
  "unpkg.com",
  "cdn.jsdelivr.net",
  "googletagmanager.com",
  "google-analytics.com"
];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...walk(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

function distTextFiles(): { path: string; text: string }[] {
  let files: string[];
  try {
    files = walk(DIST);
  } catch {
    throw new Error(`missing ${DIST}; run \`npm run build\` before the bundle contract test`);
  }
  return files
    .filter((file) => TEXT_EXT.has(file.slice(file.lastIndexOf("."))))
    .map((file) => ({ path: file, text: readFileSync(file, "utf8") }));
}

describe("dashboard bundle is offline / air-gapped", () => {
  const files = distTextFiles();

  it("built at least the index + a hashed asset", () => {
    expect(files.some((f) => f.path.endsWith("index.html"))).toBe(true);
    expect(files.some((f) => /assets\/index-.*\.js$/.test(f.path))).toBe(true);
  });

  it("references no external font/CDN/analytics host", () => {
    const offenders: string[] = [];
    for (const { path, text } of files) {
      for (const host of FORBIDDEN_HOSTS) {
        if (text.includes(host)) {
          offenders.push(`${path} -> ${host}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("loads fonts only from the self-hosted /fonts/ path", () => {
    const css = files.filter((f) => f.path.endsWith(".css"));
    expect(css.length).toBeGreaterThan(0);
    for (const { text } of css) {
      // Every @font-face src must be a same-origin /fonts/*.woff2 URL.
      const srcUrls = [...text.matchAll(/src:\s*url\(([^)]+)\)/g)].map((m) =>
        m[1].replace(/["']/g, "")
      );
      for (const url of srcUrls) {
        expect(url.startsWith("/fonts/")).toBe(true);
        expect(/^https?:\/\//.test(url)).toBe(false);
      }
    }
  });
});
