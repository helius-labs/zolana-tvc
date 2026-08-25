import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    protocol: "src/protocol.ts",
    browser: "src/browser.ts",
    "shielded-wallet": "src/shielded-wallet.ts",
    "enclave/index": "src/enclave/index.ts",
    "enclave/browser": "src/enclave/browser.ts",
    "enclave/react": "src/enclave/react.tsx",
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
