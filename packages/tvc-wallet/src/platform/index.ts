export type TvcTransport = {
  fetch(input: URL, init?: RequestInit): Promise<Response>;
};

export function createDefaultTransport(): TvcTransport {
  return {
    fetch: (input, init) => fetch(input, init),
  };
}
