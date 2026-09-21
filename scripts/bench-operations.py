#!/usr/bin/env python3
"""Benchmark encrypted TVC handlers locally; never contacts Turnkey or a real prover."""

import argparse
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def stub_prover():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/prove"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["circuitType"] == "transfer-ring"
            assert all(isinstance(item["nullifierSecret"], str) for item in body["inputs"])
            delay = body.get("benchmarkDelayMs", 0)
            assert delay in (0, 50)
            time.sleep(delay / 1000)
            response = b'{"proof":"benchmark-stub"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def report(output, metadata, measurements, rate):
    groups = {}
    for row in measurements:
        groups.setdefault((row["name"], row["batch_size"]), []).append(row)
    rows = []
    for (name, size), runs in sorted(groups.items()):
        median = lambda key: statistics.median(r[key] for r in runs)
        cpu = median("cpu_mean_ms")
        rows.append({
            "name": name, "batch_size": size, "samples": sum(r["samples"] for r in runs),
            "cpu_mean_ms": cpu, "cpu_mean_run_min_ms": min(r["cpu_mean_ms"] for r in runs),
            "cpu_mean_run_max_ms": max(r["cpu_mean_ms"] for r in runs),
            "wall_p50_ms": median("wall_p50_ms"), "wall_p95_ms": median("wall_p95_ms"),
            "cost_per_million_calls_usd": cpu * rate / 3.6,
            "cost_per_million_items_usd": cpu * rate / 3.6 / size,
            "request_bytes": runs[0]["request_bytes"], "response_bytes": runs[0]["response_bytes"],
        })
    result = {"metadata": metadata, "vcpu_hour_usd": rate, "summary": rows, "runs": measurements}
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = [
        "# TVC operation benchmark", "",
        f"Measured {metadata['measured_at']} on {metadata['cpu_model']}; Linux CPU affinity {metadata['benchmark_cpu']}. "
        f"Native release build, {metadata['rustc'].splitlines()[0]}. "
        f"Source HEAD `{metadata['git_head']}`; benchmark source SHA-256 `{metadata['benchmark_source_sha256']}`.", "",
        "Real Axum encrypted handlers: request parsing, envelope decryption, descriptor/client authorization, "
        "seed unsealing and role expansion, operation work, response encryption, and App Proof signing. "
        "Client request construction and client response verification are outside the measured intervals. "
        "Every response is decrypted, authenticated, and checked. No real wallets or transactions are used.", "",
        "CPU uses CLOCK_PROCESS_CPUTIME_ID (user and system CPU across the benchmark process); wall time uses a monotonic clock. "
        "The async runtime has one thread. Ten warmups precede each case. "
        "Each run collects the requested measured wall duration and minimum sample count; "
        "the 50 ms wait case caps its minimum at 20 samples. Repetition order alternates. "
        "The table reports the median run's mean CPU and the medians of run p50/p95 latency, not pooled quantiles. "
        "Raw per-run summaries and sample counts are in results.json.", "",
        "Bootstrap uses an in-process Ed25519 signer and empty custody evidence: Turnkey HTTP, owner approval, "
        "and production custody response handling are excluded. Prove uses a separate-process loopback stub "
        "that checks secret insertion and returns a synthetic proof; the stub's CPU is excluded. "
        "Its named payload sizes are synthetic padding sizes, not measured real circuit witnesses. "
        "No ZK proof is generated. Decrypt items contain 128 plaintext bytes; derivations use distinct synthetic field values.", "",
        f"Costs use ${rate:.2f}/vCPU-hour and CPU work only: `USD per million calls = CPU ms × rate / 3.6`. "
        "They exclude idle capacity, replicas, external proving, Turnkey API charges, network, "
        "App Runner, and client-side Boot Proof verification. These are local host measurements, "
        "not Nitro/QOS deployment benchmarks. The production image uses musl; this build uses the host target.", "",
        "| Operation | Items | CPU mean ms | Run CPU range ms | Wall p50 ms | Wall p95 ms | $ / 1M calls | $ / 1M items |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(f"| {row['name']} | {row['batch_size']} | {row['cpu_mean_ms']:.3f} | "
                     f"{row['cpu_mean_run_min_ms']:.3f}–{row['cpu_mean_run_max_ms']:.3f} | "
                     f"{row['wall_p50_ms']:.3f} | {row['wall_p95_ms']:.3f} | "
                     f"{row['cost_per_million_calls_usd']:.3f} | {row['cost_per_million_items_usd']:.4f} |")
    lines += ["", f"A continuously provisioned vCPU costs ${rate * 24 * 30:.2f} per 30-day month. "
              "For a CPU-bound workload at 30% effective utilization, multiply these CPU costs by 3.33. "
              "For a deployed service, measure sustained completed requests per second and use "
              "`USD per call = hourly fleet cost / (3600 × requests per second)`. "
              "The sequential latency samples here are not a saturation/load test.", "",
              "Reproduce with:", "", "```sh", metadata["reproduce"], "```", ""]
    (output / "report.md").write_text("\n".join(lines))
    print(f"Report: {output / 'report.md'}", flush=True)
    print(f"Raw results: {output / 'results.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=1)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--vcpu-hour", type=float, default=0.68)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "target/operation-benchmarks/latest")
    parser.add_argument("--stub-prover", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.stub_prover:
        stub_prover()
        return
    if platform.system() != "Linux":
        parser.error("CPU affinity and process CPU measurement currently require Linux")
    if not (0 < args.seconds <= 30 and args.samples > 0 and args.repeats > 0 and args.vcpu_hour > 0):
        parser.error("seconds must be in (0, 30]; samples, repeats, and vcpu-hour must be positive")
    allowed = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed[0]
    if cpu not in allowed:
        parser.error(f"CPU {cpu} is outside this process's CPU affinity")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    print("Building the release benchmark...", flush=True)
    with (output / "build.log").open("w") as log:
        build = subprocess.run([
            "cargo", "build", "--locked", "--release", "--features", "local-dev",
            "-p", "zolana-tvc-privacy-wallet", "--example", "operations-benchmark", "--message-format=json",
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=log, text=True)
    (output / "build-artifacts.jsonl").write_text(build.stdout)
    if build.returncode:
        raise SystemExit(f"Build failed; see {output / 'build.log'} and build-artifacts.jsonl")
    artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
    executable = next(a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "operations-benchmark" and a.get("executable"))
    source_paths = [ROOT / "apps/privacy-wallet/examples/operations-benchmark.rs", pathlib.Path(__file__), ROOT / "Cargo.lock"]
    digest = hashlib.sha256()
    for path in source_paths:
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    cpu_model = next(line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
    metadata = {
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cpu_model": cpu_model, "benchmark_cpu": cpu, "allowed_cpus": allowed,
        "kernel": platform.release(), "rustc": command("rustc", "-vV"),
        "git_head": command("git", "rev-parse", "HEAD"), "git_status": command("git", "status", "--short"),
        "benchmark_source_sha256": digest.hexdigest(), "executable_sha256": hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest(),
        "seconds": args.seconds, "minimum_samples": args.samples, "repeats": args.repeats,
        "rustflags": os.environ.get("RUSTFLAGS", ""),
        "reproduce": f"python3 scripts/bench-operations.py --seconds {args.seconds:g} --samples {args.samples} --repeats {args.repeats} --cpu {cpu} --vcpu-hour {args.vcpu_hour:g}",
    }
    stub = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), "--stub-prover"], stdout=subprocess.PIPE, text=True)
    try:
        url = stub.stdout.readline().strip()
        if not url.startswith("http://127.0.0.1:"):
            raise RuntimeError("Loopback prover stub did not start")
        stub_cpu = next((c for c in allowed if c != cpu), cpu)
        os.sched_setaffinity(stub.pid, {stub_cpu})
        metadata["stub_cpu"] = stub_cpu
        with (output / "raw.json").open("w") as raw:
            subprocess.run([
                "taskset", "--cpu-list", str(cpu), executable,
                "--prover-url", url, "--seconds", str(args.seconds),
                "--samples", str(args.samples), "--repeats", str(args.repeats),
            ], cwd=ROOT, stdout=raw, check=True)
        measurements = json.loads((output / "raw.json").read_text())
        report(output, metadata, measurements, args.vcpu_hour)
    finally:
        stub.terminate()
        try:
            stub.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stub.kill()
            stub.wait()


if __name__ == "__main__":
    main()
