export class TvcError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "TvcError";
    this.code = code;
  }
}
