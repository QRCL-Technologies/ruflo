import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import { request as httpRequest, type Server } from 'node:http';
import { WebSocket } from 'ws';

import { HttpTransport } from '../src/transport/http.js';
import { WebSocketTransport } from '../src/transport/websocket.js';
import { isAllowedHostHeader, isAllowedOrigin } from '../src/transport/origin-guard.js';
import type { ILogger, ITransport } from '../src/types.js';

const RPC = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'terminal_execute' } };
const logger: ILogger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

let transport: ITransport | undefined;
let handled = 0;
let port = 0;

async function startHttp(extra: Record<string, unknown> = {}): Promise<void> {
  handled = 0;
  const t = new HttpTransport(logger, { host: '127.0.0.1', port: 0, ...extra });
  t.onRequest(async (r) => {
    handled++;
    return { jsonrpc: '2.0', id: r.id, result: { ok: true } };
  });
  await t.start();
  transport = t;
  port = ((t as unknown as { server: Server }).server.address() as AddressInfo).port;
}

async function startWs(extra: Record<string, unknown> = {}): Promise<void> {
  handled = 0;
  const t = new WebSocketTransport(logger, { host: '127.0.0.1', port: 0, ...extra });
  t.onRequest(async (r) => {
    handled++;
    return { jsonrpc: '2.0', id: r.id, result: { ok: true } };
  });
  await t.start();
  transport = t;
  port = ((t as unknown as { server: Server }).server.address() as AddressInfo).port;
}

type WsOutcome = { opened: true; reply: unknown } | { opened: false; status: number };

function connect(opts: { origin?: string; host?: string; query?: string } = {}): Promise<WsOutcome> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws${opts.query ?? ''}`, {
      origin: opts.origin,
      headers: opts.host ? { host: opts.host } : undefined,
    });
    ws.on('unexpected-response', (_req, res) => {
      resolve({ opened: false, status: res.statusCode ?? 0 });
      ws.terminate();
    });
    ws.on('open', () => ws.send(JSON.stringify(RPC)));
    ws.on('message', (data) => {
      resolve({ opened: true, reply: JSON.parse(data.toString()) });
      ws.close();
    });
    ws.on('error', (err) => {
      if (!/Unexpected server response/.test(String(err))) reject(err);
    });
  });
}

afterEach(async () => {
  await transport?.stop();
  transport = undefined;
  vi.clearAllMocks();
});

describe('HTTP transport /ws cross-site WebSocket hijacking guard', () => {
  it('a CLI client without an Origin header still connects and is served', async () => {
    await startHttp();
    const out = await connect();
    expect(out).toMatchObject({ opened: true, reply: { id: 1, result: { ok: true } } });
    expect(handled).toBe(1);
  });

  it('refuses the upgrade from a foreign web page (no auth, default config)', async () => {
    await startHttp();
    for (const origin of ['http://example.test', 'https://evil.example', 'null', 'http://localhost:9999']) {
      expect(await connect({ origin })).toEqual({ opened: false, status: 403 });
    }
    expect(handled).toBe(0);
  });

  it('a wildcard origin list does not open an unauthenticated server to every page', async () => {
    await startHttp({ corsOrigins: ['*'] });
    expect(await connect({ origin: 'http://example.test' })).toEqual({ opened: false, status: 403 });
    expect(handled).toBe(0);
  });

  it('accepts an explicitly allowlisted origin', async () => {
    await startHttp({ corsOrigins: ['https://app.example'] });
    expect(await connect({ origin: 'https://app.example' })).toMatchObject({ opened: true });
    expect(await connect({ origin: 'https://evil.example' })).toEqual({ opened: false, status: 403 });
    expect(handled).toBe(1);
  });

  it('refuses a rebound Host header on a loopback bind', async () => {
    await startHttp();
    expect(await connect({ host: `rebind.evil.example:${port}` })).toEqual({ opened: false, status: 403 });
    expect(await connect({ host: `localhost:${port}` })).toMatchObject({ opened: true });
  });

  it('with auth enabled, a foreign origin is still refused before the token check', async () => {
    await startHttp({ auth: { enabled: true, method: 'token', tokens: ['tok-123456789'] } });
    expect(await connect({ origin: 'http://example.test', query: '?token=tok-123456789' })).toEqual({ opened: false, status: 403 });
    expect(await connect({ query: '?token=tok-123456789' })).toMatchObject({ opened: true });
  });
});

describe('HTTP transport DNS-rebinding guard on /rpc and /mcp', () => {
  const post = (path: string, headers: Record<string, string> = {}) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(RPC),
    });

  it('rejects requests whose Host is not a loopback name', async () => {
    await startHttp();
    for (const path of ['/rpc', '/mcp']) {
      const status = await new Promise<number>((resolve, reject) => {
        const body = JSON.stringify(RPC);
        const req = httpRequest(
          { host: '127.0.0.1', port, path, method: 'POST', headers: { host: 'rebind.evil.example', 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
          (res) => { res.resume(); resolve(res.statusCode ?? 0); },
        );
        req.on('error', reject);
        req.end(body);
      });
      expect(status).toBe(403);
    }
    expect(handled).toBe(0);
    expect((await post('/rpc')).status).toBe(200);
  });

  it('a wildcard CORS list does not let a foreign page call an unauthenticated server', async () => {
    await startHttp({ corsOrigins: ['*'] });
    expect((await post('/rpc', { origin: 'http://example.test' })).status).toBeGreaterThanOrEqual(400);
    expect(handled).toBe(0);
  });
});

describe('standalone WebSocket transport guard', () => {
  it('refuses foreign origins and rebound hosts, accepts CLI clients and allowlisted origins', async () => {
    await startWs({ allowedOrigins: ['https://app.example'] });
    expect(await connect({ origin: 'http://example.test' })).toEqual({ opened: false, status: 403 });
    expect(await connect({ host: 'rebind.evil.example' })).toEqual({ opened: false, status: 403 });
    expect(handled).toBe(0);
    expect(await connect()).toMatchObject({ opened: true });
    expect(await connect({ origin: 'https://app.example' })).toMatchObject({ opened: true });
    expect(handled).toBe(2);
  });
});

describe('origin-guard helpers', () => {
  it('isAllowedOrigin', () => {
    expect(isAllowedOrigin(undefined, undefined, false)).toBe(true);
    expect(isAllowedOrigin('http://a.test', undefined, false)).toBe(false);
    expect(isAllowedOrigin('http://a.test', ['*'], false)).toBe(false);
    expect(isAllowedOrigin('http://a.test', ['*'], true)).toBe(true);
    expect(isAllowedOrigin('HTTP://A.test/', ['http://a.test'], false)).toBe(true);
    expect(isAllowedOrigin('null', ['http://a.test'], false)).toBe(false);
  });

  it('isAllowedHostHeader', () => {
    expect(isAllowedHostHeader(undefined, '127.0.0.1')).toBe(true);
    expect(isAllowedHostHeader('localhost:3000', '127.0.0.1')).toBe(true);
    expect(isAllowedHostHeader('127.0.0.1:3000', '127.0.0.1')).toBe(true);
    expect(isAllowedHostHeader('[::1]:3000', '::1')).toBe(true);
    expect(isAllowedHostHeader('LOCALHOST.', 'localhost')).toBe(true);
    expect(isAllowedHostHeader('evil.test:3000', '127.0.0.1')).toBe(false);
    expect(isAllowedHostHeader('127.0.0.1.evil.test', '127.0.0.1')).toBe(false);
    expect(isAllowedHostHeader('dev.box:3000', '127.0.0.1', ['dev.box'])).toBe(true);
    expect(isAllowedHostHeader('anything', '0.0.0.0')).toBe(true);
    expect(isAllowedHostHeader('other', '0.0.0.0', ['mcp.internal'])).toBe(false);
  });
});
