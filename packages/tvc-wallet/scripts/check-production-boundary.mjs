import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const roots = [
  "dist/index.js",
  "dist/protocol.js",
  "dist/browser.js",
  "dist/react/index.js",
  "dist/index.cjs",
  "dist/protocol.cjs",
  "dist/browser.cjs",
  "dist/react/index.cjs",
];
const localTestkitMarkers = /local-unattested|connectLocalUnattested|LocalTvcSession/;
const relativeModule = /\.\.?\/[A-Za-z0-9/_-]+\.(?:c?js)/g;
const visited = new Set();

function inspect(relativePath) {
  const file = resolve(packageRoot, relativePath);
  if (visited.has(file)) return;
  visited.add(file);
  const source = readFileSync(file, "utf8");
  if (localTestkitMarkers.test(source)) {
    throw new Error(`local testkit code is reachable from a production entry: ${relativePath}`);
  }
  for (const specifier of source.match(relativeModule) ?? []) {
    inspect(resolve(dirname(file), specifier));
  }
}

for (const root of roots) inspect(root);
