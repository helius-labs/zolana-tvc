// Answers the two Turnkey queries tvc-gateway's ownership checks make. Every
// sub-org is named MOCK_PROJECT_ID and every wallet holds MOCK_WALLET_ADDRESS.
import { createServer } from "node:http";

const port = Number(process.env.MOCK_TURNKEY_PORT ?? "8941");
const projectId = required("MOCK_PROJECT_ID");
const walletAddress = required("MOCK_WALLET_ADDRESS");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function reply(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

const routes = {
  "/public/v1/query/whoami": (request) => ({
    organizationId: request.organizationId,
    organizationName: projectId,
    userId: "mock-user",
    username: "mock",
  }),
  "/public/v1/query/list_wallet_accounts": (request) => ({
    accounts: [
      {
        walletAccountId: "mock-account",
        organizationId: request.organizationId,
        walletId: request.walletId,
        curve: "CURVE_ED25519",
        pathFormat: "PATH_FORMAT_BIP32",
        path: "m/44'/501'/0'/0'",
        addressFormat: "ADDRESS_FORMAT_SOLANA",
        address: walletAddress,
      },
    ],
  }),
};

createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", () => {
    const route = routes[request.url];
    console.error(`mock-turnkey ${request.method} ${request.url}`);
    if (!route) return reply(response, 404, { code: 5, message: "not found" });
    reply(response, 200, route(JSON.parse(body || "{}")));
  });
}).listen(port, "127.0.0.1", () => console.error(`mock-turnkey listening on ${port}`));
