/** Bounded live TVC benchmark. No transactions are signed or submitted. */
import "dotenv/config";
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import {
  SOL_MINT, Wallet, buildTransferTransaction, syncWallet,
} from "@heliuslabs/zolana";
import { P256PublicKey, ViewingKey, type Bytes16, type Bytes33 } from "@heliuslabs/zolana/keypair";
import { parseProof } from "@heliuslabs/zolana/client";
import { TvcKeys, identityOf, shieldedAddressOf, type TvcClient } from "@zolana/tvc-wallet";
import type { DecryptItem, DeriveItem, TransactionKeyItem } from "@zolana/tvc-wallet/protocol";
import { setup, type StoredWallet } from "../src/lib.js";

const { values } = parseArgs({ options: {
  samples: { type: "string", default: "20" },
  "app-id": { type: "string" },
  "vcpus-per-replica": { type: "string" },
  "require-server-cpu": { type: "boolean", default: false },
  mixed: { type: "boolean", default: false },
  "max-rps": { type: "string", default: "0" },
  repeats: { type: "string", default: "3" },
  concurrency: { type: "string", default: "1,4" },
  bootstraps: { type: "string", default: "3" },
  proofs: { type: "string", default: "3" },
  "boot-proof-cache-ms": { type: "string", default: "0" },
  output: { type: "string", default: "../../target/live-operation-benchmarks/latest" },
} });
const integer = (value: string, max: number) => {
  const number = Number(value);
  assert(Number.isInteger(number) && number > 0 && number <= max);
  return number;
};
const samples = integer(values.samples, values.mixed ? 1000 : 100);
const repeats = integer(values.repeats, 3);
const maxRps = Number(values["max-rps"]);
assert(Number.isFinite(maxRps) && maxRps >= 0 && maxRps <= 100);

const concurrencies = values.concurrency.split(",").map(v => integer(v, values.mixed ? 32 : 8));
const bootstrapSamples = integer(values.bootstraps, 5);
const proofSamples = integer(values.proofs, 5);
const bootProofCacheMs = Number(values["boot-proof-cache-ms"]);
assert(Number.isInteger(bootProofCacheMs) && bootProofCacheMs >= 0 && bootProofCacheMs <= 60_000);
const endpoint = new URL(process.env["TVC_ENDPOINT"] ?? "");
assert.equal(endpoint.protocol, "https:");
const appId = values["app-id"] ?? /^app-([0-9a-f-]+)\.app\.turnkey\.cloud$/.exec(endpoint.hostname)?.[1];
assert(appId, "Set TVC_ENDPOINT to the deployed app URL or specify --app-id");
assert(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(appId));
assert.equal(endpoint.hostname, `app-${appId}.app.turnkey.cloud`);
const vcpusPerReplica = values["vcpus-per-replica"] === undefined ? null : Number(values["vcpus-per-replica"]);
assert(vcpusPerReplica === null || (Number.isFinite(vcpusPerReplica) && vcpusPerReplica > 0), "--vcpus-per-replica must be positive");
assert(!process.env["TVC_LOCAL_TESTKIT_ENDPOINT"], "This benchmark must use real TVC");
const output = resolve(values.output);
await mkdir(output, { recursive: true });

interface ServerCpu { taskUs: number; processStartUs: number; processEndUs: number; wallStartUs: number; wallEndUs: number }
interface CallTiming { serverCpu?: ServerCpu; operation?: string; retryAfter?: string; httpErrorInfo?: { headers: Record<string, string>; indicators: string[] }; totalMs: number; tvcHttpMs: number[]; status: number[]; replicas: string[] }
interface CaseResult {
  name: string; batchSize: number; concurrency: number; repeat: number;
  calls: number; elapsedMs: number; successfulCallsPerSecond: number; clientCpuMs: number; clientCpuCores: number; operationCounts: Record<string, number>;
  sdkP50Ms: number; sdkP95Ms: number; httpP50Ms: number; httpP95Ms: number;
  replicasObserved: number; timings: CallTiming[]; serverCpu?: ReturnType<typeof summarizeServerCpu>;
}
const context = new AsyncLocalStorage<CallTiming>();
const originalFetch = globalThis.fetch;
const bootProofStats = { networkRequests: 0, cacheHits: 0, coalescedRequests: 0, failures: [] as { status: number; code?: number }[] };
const bootProofCache = new Map<string, { expiresAt: number; response: Response }>();
const pendingBootProofs = new Map<string, Promise<Response>>();
// This opt-in benchmark profile caches public evidence, never verification.
// The SDK rechecks each App Proof and the cached Boot Proof against its trust pins.
async function fetchBootProof(input: Parameters<typeof fetch>[0], init: Parameters<typeof fetch>[1], key: string): Promise<Response> {
  const cached = bootProofCache.get(key);
  if (cached && cached.expiresAt > performance.now()) {
    bootProofStats.cacheHits++;
    return cached.response.clone();
  }
  const pending = pendingBootProofs.get(key);
  if (pending) {
    bootProofStats.coalescedRequests++;
    return (await pending).clone();
  }
  const request = (async () => {
    bootProofStats.networkRequests++;
    const response = await originalFetch(input, init);
    if (!response.ok) {
      const error = await response.clone().json().catch(() => ({})) as { code?: unknown };
      bootProofStats.failures.push({ status: response.status, ...(typeof error.code === "number" ? { code: error.code } : {}) });
      return response;
    }
    const buffered = new Response(await response.arrayBuffer(), { status: response.status, headers: response.headers });
    if (bootProofCacheMs > 0) {
      for (const [entryKey, entry] of bootProofCache) {
        if (entry.expiresAt <= performance.now()) bootProofCache.delete(entryKey);
      }
      if (bootProofCache.size < 16 || bootProofCache.has(key)) {
        bootProofCache.set(key, { expiresAt: performance.now() + bootProofCacheMs, response: buffered.clone() });
      }
    }
    return buffered;
  })();
  if (bootProofCacheMs > 0) pendingBootProofs.set(key, request);
  try {
    return (await request).clone();
  } finally {
    if (pendingBootProofs.get(key) === request) pendingBootProofs.delete(key);
  }
}
// Only the app's HTTP exchange is timed here. The SDK still verifies every
// encrypted result, App Proof, release pin, and Boot Proof normally.
globalThis.fetch = async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.origin === "https://api.turnkey.com" && url.pathname === "/public/v1/query/get_boot_proof" && typeof init?.body === "string") {
    const body = JSON.parse(init.body) as { organizationId?: string; ephemeralKey?: string };
    if (body.organizationId === process.env["TVC_ORGANIZATION_ID"] && typeof body.ephemeralKey === "string") {
      return fetchBootProof(input, init, `${body.organizationId}:${body.ephemeralKey}`);
    }
  }
  const active = context.getStore();
  if (!active || url.origin !== endpoint.origin || url.pathname !== "/v1/operations") {
    return originalFetch(input, init);
  }
  const start = performance.now();
  const response = await originalFetch(input, init);
  const body = await response.clone().arrayBuffer();
  active.tvcHttpMs.push(performance.now() - start);
  active.status.push(response.status);
  const retryAfter = response.headers.get("retry-after");
  if (retryAfter && /^(?:\d{1,10}|[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT)$/.test(retryAfter)) active.retryAfter = retryAfter;
  if (!response.ok) {
    const headers: Record<string, string> = {};
    for (const name of ["server", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "x-envoy-overloaded"]) {
      const value = response.headers.get(name);
      if (value && value.length < 200) headers[name] = value;
    }
    const text = new TextDecoder().decode(body).toLowerCase();
    active.httpErrorInfo = { headers, indicators: ["rate limit", "too many requests", "concurrent", "overload", "quota", "capacity"].filter(value => text.includes(value)) };
  }
  if (response.ok) {
    const header = response.headers.get("x-tvc-benchmark-cpu");
    if (header) {
      const match = /^task_us=(\d+),process_start_us=(\d+),process_end_us=(\d+),wall_start_us=(\d+),wall_end_us=(\d+)$/.exec(header);
      assert(match, "Invalid server CPU counters");
      const counters = match.slice(1).map(Number);
      assert(counters.every(v => Number.isSafeInteger(v) && v >= 0));
      const [taskUs, processStartUs, processEndUs, wallStartUs, wallEndUs] = counters as [number, number, number, number, number];
      assert(processEndUs >= processStartUs && wallEndUs >= wallStartUs);
      active.serverCpu = { taskUs, processStartUs, processEndUs, wallStartUs, wallEndUs };
    }
    assert(!values["require-server-cpu"] || active.serverCpu, "Server CPU counters missing from instrumented response");
    const envelope = JSON.parse(new TextDecoder().decode(body)) as { tvc_app_proof?: { public_key?: string } };
    if (envelope.tvc_app_proof?.public_key) active.replicas.push(envelope.tvc_app_proof.public_key);
  }
  // Neither requests nor decrypted results are logged or saved.
  return response;
};

function percentile(numbers: number[], p: number): number {
  const sorted = [...numbers].sort((a, b) => a - b);
  assert(sorted.length);
  return sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)]!;
}
function summarizeServerCpu(timings: CallTiming[], concurrency: number) {
  if (!timings.every(t => t.serverCpu)) return undefined;
  const cpu = timings.map(t => t.serverCpu!);
  const mean = (v: number[]) => v.reduce((a, b) => a + b, 0) / v.length;
  const replicas = [...new Set(timings.flatMap(t => t.replicas))];
  const windows = replicas.map((replica, index) => {
    const records = timings.filter(t => t.replicas.includes(replica)).map(t => t.serverCpu!);
    const processCpuMs = (Math.max(...records.map(c => c.processEndUs)) - Math.min(...records.map(c => c.processStartUs))) / 1000;
    const wallMs = (Math.max(...records.map(c => c.wallEndUs)) - Math.min(...records.map(c => c.wallStartUs))) / 1000;
    const usedCores = wallMs > 0 ? processCpuMs / wallMs : null;
    return { replica: index + 1, calls: records.length, processCpuMs, wallMs, usedCores,
      percentOfAllocatedVcpus: usedCores !== null && vcpusPerReplica !== null ? usedCores / vcpusPerReplica * 100 : null };
  });
  return {
    taskCpuMeanMs: mean(cpu.map(c => c.taskUs / 1000)),
    taskCpuP50Ms: percentile(cpu.map(c => c.taskUs / 1000), 0.5),
    taskCpuP95Ms: percentile(cpu.map(c => c.taskUs / 1000), 0.95),
    // Overlapping process deltas must never be summed. This field is only
    // meaningful for sequential requests to the isolated benchmark app.
    sequentialProcessCpuMeanMs: concurrency === 1 ? mean(cpu.map(c => (c.processEndUs - c.processStartUs) / 1000)) : null,
    handlerWallMeanMs: mean(cpu.map(c => (c.wallEndUs - c.wallStartUs) / 1000)),
    handlerWallP50Ms: percentile(cpu.map(c => (c.wallEndUs - c.wallStartUs) / 1000), 0.5),
    windows,
  };
}
const results: CaseResult[] = [];
let completed = false;
let failure: string | undefined;
const startedAt = new Date().toISOString();
const metadata: Record<string, unknown> = {
  endpoint: endpoint.origin, appId, requireServerCpu: values["require-server-cpu"], serverCpuScope: "Diagnostic headers: per-future poll thread CPU and whole app-process clocks, including this process's system CPU. Excludes QOS/proxy/other host processes and the external prover. Headers are TLS-protected but not signed by the App Proof. Only sequential isolated calls support per-call process attribution.", startedAt, samples, repeats, concurrencies, mixed: values.mixed, maxRps,
  cpuMeasured: false, vcpusPerReplica, vcpuAllocationSource: vcpusPerReplica === null ? null : "--vcpus-per-replica", bootProofCacheMs, bootProofStats,
  sourceHead: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  methodology: "Live attested SDK calls; HTTP round trip includes network, ingress, queueing, enclave work, and response download. SDK latency also includes client cryptography and Boot Proof lookups. Throughput is achieved by this bounded client workload, not a saturation estimate. Server CPU counters are collected only when present in an explicitly instrumented build.",
};
async function persist() {
  const serialized = results.map(r => ({ ...r, timings: r.timings.map(t => ({ ...t, replicas: undefined })) }));
  await writeFile(resolve(output, "results.json"), JSON.stringify({ metadata, completed, failure, results: serialized }, null, 2) + "\n");
}
async function measure(name: string, batchSize: number, count: number, concurrency: number, repeat: number, run: () => Promise<void>) {
  const timings: CallTiming[] = [];
  const failedCalls: { operation?: string; retryAfter?: string; httpErrorInfo?: CallTiming["httpErrorInfo"]; status: number[]; elapsedMs: number; errorClass: string; code?: string }[] = [];
  let next = 0;
  let stopped = false;
  const start = performance.now();
  let nextStartAt = start;
  const cpuStart = process.cpuUsage();
  const workers = Array.from({ length: concurrency }, async () => {
    while (!stopped && next++ < count) {
      if (maxRps > 0) {
        const slot = Math.max(nextStartAt, performance.now());
        nextStartAt = slot + 1000 / maxRps;
        await delay(Math.max(0, slot - performance.now()));
        if (stopped) return;
      }
      const timing: CallTiming = { totalMs: 0, tvcHttpMs: [], status: [], replicas: [] };
      const begin = performance.now();
      try {
        await context.run(timing, run);
        timing.totalMs = performance.now() - begin;
        assert.equal(timing.tvcHttpMs.length, 1, "Expected exactly one TVC operation per measured SDK call");
        assert(timing.status.every(status => status === 200));
        timings.push(timing);
      } catch (error) {
        stopped = true;
        failedCalls.push({ operation: timing.operation, retryAfter: timing.retryAfter, httpErrorInfo: timing.httpErrorInfo, status: timing.status, elapsedMs: performance.now() - begin,
          errorClass: error instanceof Error ? error.name : "UnknownError",
          ...(error instanceof Error && "code" in error ? { code: String(error.code) } : {}),
        });
        throw error;
      }
    }
  });
  const outcomes = await Promise.allSettled(workers);
  const rejected = outcomes.find((outcome): outcome is PromiseRejectedResult => outcome.status === "rejected");
  if (rejected) {
    const cpu = process.cpuUsage(cpuStart);
    metadata["failedStage"] = { name, batchSize, concurrency, repeat, successfulCalls: timings.length,
      elapsedMs: performance.now() - start, clientCpuMs: (cpu.user + cpu.system) / 1000, failedCalls, successfulReplicasObserved: new Set(timings.flatMap(t => t.replicas)).size,
      successfulTimings: timings.map(t => ({ ...t, replicas: undefined })),
    };
    throw rejected.reason;
  }
  const elapsedMs = performance.now() - start;
  const cpu = process.cpuUsage(cpuStart);
  const clientCpuMs = (cpu.user + cpu.system) / 1000;
  const operationCounts: Record<string, number> = {};
  for (const timing of timings) {
    const operation = timing.operation ?? name;
    operationCounts[operation] = (operationCounts[operation] ?? 0) + 1;
  }
  const result: CaseResult = {
    name, batchSize, concurrency, repeat, calls: timings.length, elapsedMs, clientCpuMs, clientCpuCores: clientCpuMs / elapsedMs, operationCounts,
    successfulCallsPerSecond: timings.length * 1000 / elapsedMs,
    sdkP50Ms: percentile(timings.map(t => t.totalMs), 0.5),
    sdkP95Ms: percentile(timings.map(t => t.totalMs), 0.95),
    httpP50Ms: percentile(timings.flatMap(t => t.tvcHttpMs), 0.5),
    httpP95Ms: percentile(timings.flatMap(t => t.tvcHttpMs), 0.95),
    replicasObserved: new Set(timings.flatMap(t => t.replicas)).size, timings,
  };
  result.serverCpu = summarizeServerCpu(timings, concurrency);
  if (result.serverCpu) metadata["cpuMeasured"] = true;
  results.push(result);
  console.log(`${name} batch=${batchSize} concurrency=${concurrency} repeat=${repeat}: HTTP p50=${result.httpP50Ms.toFixed(1)}ms p95=${result.httpP95Ms.toFixed(1)}ms, SDK p50=${result.sdkP50Ms.toFixed(1)}ms, ${result.successfulCallsPerSecond.toFixed(2)} calls/s, client CPU=${result.clientCpuCores.toFixed(2)} cores`);
  await persist();
}
const field = (i: number) => i.toString(16).padStart(64, "0");

try {
  metadata["appStatusBefore"] = JSON.parse(execFileSync("tvc", ["app", "status", "--app-id", appId, "--message-format", "json"], { encoding: "utf8" }));
  const { tvc, connection, walletPath, zolana, signer } = await setup();
  metadata["verifiedReleaseId"] = connection.releaseId;
  const stored = JSON.parse(await readFile(walletPath, "utf8")) as StoredWallet;
  assert.equal(stored.identity.solanaAddress, signer.address);
  const signal = () => AbortSignal.timeout(90_000);
  console.log(`Verified real TVC release ${connection.releaseId}; using the configured devnet test wallet. Public Boot Proof cache: ${bootProofCacheMs}ms.`);

  if (!values.mixed) await measure("Bootstrap/real-Turnkey-approval", 1, bootstrapSamples, 1, 1, async () => {
    const result = await tvc.bootstrap(connection, { expectedIdentity: stored.identity, signal: signal() });
    assert.deepEqual(identityOf(result), stored.identity);
  });

  const ephemeral = ViewingKey.generate();
  const recipient = P256PublicKey.fromBytes(Buffer.from(stored.identity.shieldedViewingPublicKey, "hex") as unknown as Bytes33);
  const plaintext = new Uint8Array(128).fill(0x5a);
  const cases: { name: string; size: number; run: () => Promise<void> }[] = [];
  for (const size of [1, 16, 128]) {
    const derive: DeriveItem[] = Array.from({ length: size }, (_, i) => ({ kind: "Nullifier", utxo_hash: field(i + 1), blinding: field(i + size + 1) }));
    const deriveExpected = await tvc.derive(connection, stored.sealedSeed, derive, { signal: signal() });
    cases.push({ name: "Derive/nullifier", size, run: async () => {
      assert.deepEqual(await tvc.derive(connection, stored.sealedSeed, derive, { signal: signal() }), deriveExpected);
    } });
    const txKeys: TransactionKeyItem[] = Array.from({ length: size }, (_, i) => ({ viewing_public_key: stored.identity.shieldedViewingPublicKey, first_nullifier: field(i + 1) }));
    const keysExpected = await tvc.transactionKeys(connection, stored.sealedSeed, txKeys, { signal: signal() });
    cases.push({ name: "TransactionKeys", size, run: async () => {
      assert.deepEqual(await tvc.transactionKeys(connection, stored.sealedSeed, txKeys, { signal: signal() }), keysExpected);
    } });
    const decrypt: DecryptItem[] = Array.from({ length: size }, (_, i) => {
      const salt = new Uint8Array(16) as Bytes16;
      new DataView(salt.buffer).setUint32(12, i);
      return {
        label: "Transfer", slot_index: String(i), salt: Buffer.from(salt).toString("hex"),
        viewing_public_key: stored.identity.shieldedViewingPublicKey,
        transaction_viewing_public_key: Buffer.from(ephemeral.publicKey().toBytes()).toString("hex"),
        ciphertext: Buffer.from(ephemeral.encryptSlot(recipient, plaintext, salt, i)).toString("hex"),
      };
    });
    cases.push({ name: "Decrypt/transfer", size, run: async () => {
      assert.deepEqual(await tvc.decrypt(connection, stored.sealedSeed, decrypt, { signal: signal() }), Array(size).fill(Buffer.from(plaintext).toString("hex")));
    } });
  }
  for (let repeat = 1; !values.mixed && repeat <= repeats; repeat++) {
    for (const test of repeat % 2 ? cases : [...cases].reverse()) {
      await test.run(); // warmup, excluded from timing
      for (const concurrency of concurrencies) {
        await measure(test.name, test.size, samples, concurrency, repeat, test.run);
      }
    }
  }
  // Assemble a valid real proof through the SDK using existing spendable UTXOs.
  // The transaction is discarded; no signing or submission function is called.
  let proofRequest: Parameters<TvcClient["prove"]>[2] | undefined;
  const capturingClient: TvcClient = { ...tvc, prove: async (c, s, request, options) => {
    proofRequest = structuredClone(request);
    return tvc.prove(c, s, request, options);
  } };
  const keys = new TvcKeys({ ...stored, client: capturingClient, connection });
  const wallet = new Wallet({ identity: shieldedAddressOf(stored.identity) });
  await syncWallet({ client: zolana, wallet, keys });
  assert(wallet.balance(SOL_MINT).amount > 0n, "The configured test wallet needs an existing spendable SOL UTXO to build a real proof");
  await buildTransferTransaction({
    client: zolana, wallet, keys, feePayer: signer.address,
    recipient: shieldedAddressOf(stored.identity), amount: 1n,
  });
  assert(proofRequest, "The transfer builder did not produce a TVC proof request");
  metadata["realProofCircuit"] = proofRequest["circuitType"];
  metadata["realProofRequestBytes"] = Buffer.byteLength(JSON.stringify(proofRequest));
  const realProve = async () => {
    parseProof(await tvc.prove(connection, stored.sealedSeed, proofRequest!, { signal: signal() }));
  };
  if (!values.mixed) await measure("Prove/real-external-prover", 1, proofSamples, 1, 1, realProve);
  if (values.mixed) {
    const pick = (name: string, size: number) => {
      const found = cases.find(test => test.name === name && test.size === size);
      assert(found);
      return found;
    };
    const decrypt = pick("Decrypt/transfer", 16);
    const derive = pick("Derive/nullifier", 16);
    const tx = pick("TransactionKeys", 1);
    const prove = { name: "Prove/real-external-prover", size: 1, run: realProve };
    const mix = [decrypt, derive, tx, prove, decrypt, derive, tx, prove, decrypt, derive];
    metadata["mixedWorkload"] = "30% Decrypt/16, 30% Derive/16, 20% TransactionKeys/1, 20% real Prove; the same valid proof witness is reused. No bootstrap under load.";
    for (const concurrency of concurrencies) {
      for (let repeat = 1; repeat <= repeats; repeat++) {
        let nextOperation = 0;
        await measure("Mixed", 0, samples, concurrency, repeat, async () => {
          const operation = mix[nextOperation++ % mix.length]!;
          const timing = context.getStore();
          if (timing) timing.operation = operation.name;
          await operation.run();
        });
        const latest = results.at(-1)!;
        // Keep the devnet load bounded; stop increasing load on slow responses.
        if (latest.httpP95Ms > 3_000) {
          metadata["stopReason"] = "HTTP p95 exceeded 3000 ms";
          throw new Error("LatencyStopThreshold");
        }
      }
    }
  }
  ephemeral.destroy();
  metadata["appStatusAfter"] = JSON.parse(execFileSync("tvc", ["app", "status", "--app-id", appId, "--message-format", "json"], { encoding: "utf8" }));
  completed = true;
} catch (error) {
  // Error messages from SDK assertions may carry result data: persist only the class/code.
  failure = error instanceof Error ? `${error.name}${"code" in error ? `:${String(error.code)}` : ""}` : "UnknownError";
  if (error instanceof Error && /^Operation(?:Rejected|Unavailable): HTTP \d{3}$/.test(error.message)) {
    metadata["httpFailure"] = error.message;
  }
  console.error(`Benchmark stopped: ${failure}; HTTP detail: ${String(metadata["httpFailure"] ?? "none")}`);
  process.exitCode = 1;
} finally {
  globalThis.fetch = originalFetch;
  metadata["finishedAt"] = new Date().toISOString();
  await persist();
  console.log(`Results: ${resolve(output, "results.json")}`);
}
