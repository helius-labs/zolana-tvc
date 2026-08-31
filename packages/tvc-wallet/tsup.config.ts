import { readFileSync, writeFileSync } from "node:fs";
import { defineConfig } from "tsup";

const CLIENT_ENTRIES = [
  "dist/react/index.js",
  "dist/react/index.cjs",
];

/**
 * Reapplies the `"use client"` directive to the React entry points.
 *
 * Rollup's treeshaking strips a leading directive from the bundle, and an
 * esbuild banner is treated as the same kind of directive and dropped too.
 * Rewriting the emitted files is the only placement that survives. Without it
 * the Next.js App Router treats these entries as server components and their
 * hooks fail at render.
 */
function restoreClientDirectives(): void {
  for (const file of CLIENT_ENTRIES) {
    const body = readFileSync(file, "utf8");
    if (!body.startsWith('"use client"')) {
      writeFileSync(file, `"use client";\n${body}`);
    }
  }
}

export default defineConfig({
  entry: {
    index: "src/keyholder/index.ts",
    protocol: "src/protocol.ts",
    browser: "src/keyholder/browser.ts",
    testing: "src/testing.ts",
    "react/index": "src/keyholder/react.tsx",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Shared code is hoisted into chunks instead of being copied into each of the
  // four entry points. Shared symbols are reachable from more than one entry,
  // so without this an app importing from two of them ships the client core and
  // the crypto stack twice.
  splitting: true,
  treeshake: true,
  external: ["@heliuslabs/zolana", "@solana/kit", "react", "react-dom"],
  onSuccess: async () => restoreClientDirectives(),
});
