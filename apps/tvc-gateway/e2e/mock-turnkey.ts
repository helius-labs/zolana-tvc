import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

type Route = (request: Record<string, string>) => unknown;

/**
 * Answers the Turnkey queries tvc-gateway makes: every sub-org is named
 * `projectId`, every wallet holds `walletAddress`, and any key has an
 * unattested placeholder Boot Proof.
 */
export async function startMockTurnkey(projectId: string, walletAddress: string) {
  const routes: Record<string, Route> = {
    "/public/v1/query/whoami": ({ organizationId }) => ({
      organizationId,
      organizationName: projectId,
      userId: "mock-user",
      username: "mock",
    }),
    "/public/v1/query/get_boot_proof": ({ ephemeralKey }) => ({
      bootProof: {
        ephemeralPublicKeyHex: ephemeralKey,
        awsAttestationDocB64: "",
        qosManifestB64: "",
        qosManifestEnvelopeB64: "",
        deploymentLabel: "local-unattested",
        enclaveApp: "local-unattested",
        owner: "local-unattested",
      },
    }),
    "/public/v1/query/list_wallet_accounts": ({ organizationId, walletId }) => ({
      accounts: [{
        walletAccountId: "mock-account",
        organizationId,
        walletId,
        curve: "CURVE_ED25519",
        pathFormat: "PATH_FORMAT_BIP32",
        path: "m/44'/501'/0'/0'",
        addressFormat: "ADDRESS_FORMAT_SOLANA",
        address: walletAddress,
      }],
    }),
  };
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const route = routes[request.url ?? ""];
    const [status, body] = route
      ? [200, route(JSON.parse(Buffer.concat(chunks).toString() || "{}"))]
      : [404, { code: 5, message: "not found" }];
    response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
