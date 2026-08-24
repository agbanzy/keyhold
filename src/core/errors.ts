/**
 * Errors that map to HTTP status codes. Nothing here swallows a failure: an
 * unexpected error propagates to the router boundary, which logs it and returns
 * 500. Silent fallbacks are how books stop being trustworthy.
 */

export class KeyholdError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'KeyholdError';
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      ...(this.detail !== undefined ? { detail: this.detail } : {}),
    };
  }
}

export const badRequest = (code: string, message: string, detail?: unknown) =>
  new KeyholdError(400, code, message, detail);

export const unauthorized = (code: string, message: string) =>
  new KeyholdError(401, code, message);

export const forbidden = (code: string, message: string) =>
  new KeyholdError(403, code, message);

export const notFound = (code: string, message: string) =>
  new KeyholdError(404, code, message);

export const conflict = (code: string, message: string, detail?: unknown) =>
  new KeyholdError(409, code, message, detail);

export const quotaExhausted = (action: string, limit: number) =>
  new KeyholdError(
    429,
    'quota_exhausted',
    `daily ${action} quota of ${limit} is spent; scarcity is the point`,
    { action, limit },
  );

export const notImplemented = (message: string) =>
  new KeyholdError(501, 'not_implemented', message);

export const unavailable = (code: string, message: string) =>
  new KeyholdError(503, code, message);
