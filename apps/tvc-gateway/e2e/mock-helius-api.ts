import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/** Answers `GET /v0/waas/config`: `apiKey` belongs to `projectId`, any other key is a 401. */
export async function startMockHeliusApi(apiKey: string, projectId: string) {
  const server = createServer((request, response) => {
    const known = request.method === "GET" && request.url === "/v0/waas/config"
      && request.headers["x-api-key"] === apiKey;
    const [status, body] = known
      ? [200, { projectId, organizationId: "9b98a0d8-04a4-47a3-9dc3-afa84c686de4", authProxyConfigId: "mock" }]
      : [401, { message: "Invalid API key", statusCode: 401 }];
    response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/v0`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
