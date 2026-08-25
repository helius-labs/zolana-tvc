import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    protocol: "src/protocol.ts",
    browser: "src/browser.ts",
    "shielded-wallet": "src/shielded-wallet.ts",
    "react/index": "src/react/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  external: ["@heliuslabs/zolana", "@solana/kit", "react", "react-dom"],
});
