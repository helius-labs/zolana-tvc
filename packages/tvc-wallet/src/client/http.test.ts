import { expect, it, vi } from "vitest";
import { fetchWithSignal, readBoundedText } from "./http.js";

it("stops a stalled response body even if stream cancellation never resolves", async () => {
  const controller = new AbortController();
  const cancel = vi.fn(() => new Promise<void>(() => {}));
  const response = new Response(new ReadableStream({ pull() {}, cancel }));
  const pending = readBoundedText(response, 1024n, controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(cancel).toHaveBeenCalledOnce();
});

it("cancels a response returned by a transport after its caller has left", async () => {
  const controller = new AbortController();
  let finish!: (response: Response) => void;
  const transport = { fetch: vi.fn(() => new Promise<Response>((resolve) => { finish = resolve; })) };
  const pending = fetchWithSignal(transport, new URL("https://tvc.example"), undefined, controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  controller.abort(new Error("cancelled"));
  await rejected;
  const cancel = vi.fn();
  finish(new Response(new ReadableStream({ cancel })));
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(cancel).toHaveBeenCalledOnce();
});

it("does not request or read a body for an already cancelled caller", async () => {
  const transport = { fetch: vi.fn() };
  const signal = AbortSignal.abort(new Error("cancelled"));
  await expect(fetchWithSignal(transport, new URL("https://tvc.example"), undefined, signal)).rejects.toThrow("cancelled");
  expect(transport.fetch).not.toHaveBeenCalled();
});
