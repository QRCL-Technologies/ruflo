import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { WebSocket } from 'ws';

import { WebSocketTransport } from '../src/transport/websocket.js';
import type { ILogger } from '../src/types.js';

// Cross-site WebSocket hijacking: a web page the developer visits must not be
// able to open the MCP websocket and call tools, and a configured bearer token
// must be enforced on the upgrade request.

const TOKEN = 'correct-horse-battery-staple-42';
const RPC = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'terminal_execute' } };

const logger: ILogger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
let transport: WebSocketTransport | undefined;
let handled = 0;
let url = '';

async function start(extra: Record<string, unknown> = {}): Promise<void> {
  handled = 0;
  transport = new WebSocketTransport(logger, { host: '127.0.0.1', port: 0, ...extra });
  transport.onRequest(async (r) => {
    handled++;
    return { jsonrpc: '2.0', id: r.id, result: { ok: true } };
  });
  await transport.start();
  const port = ((transport as unknown as { server: Server }).server.address() as AddressInfo).port;
  url = `ws://127.0.0.1:${port}/ws`;
}

type Outcome = { status: number } | { reply: unknown };

function connectAndCall(headers: Record<string, string> = {}): Promise<Outcome> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    ws.on('unexpected-response', (_req, res) => {
      resolve({ status: res.statusCode ?? 0 });
      ws.terminate();
    });
    ws.on('open', () => ws.send(JSON.stringify(RPC)));
    ws.on('message', (data) => {
      resolve({ reply: JSON.parse(data.toString()) });
      ws.close();
    });
    ws.on('error', (err) => {
      if (!(err.message || '').includes('Unexpected server response')) reject(err);
    });
  });
}

afterEach(async () => {
  await transport?.stop();
  transport = undefined;
});

describe('WebSocketTransport origin check', () => {
  it('rejects a browser origin by default before any tool call', async () => {
    await start();
    expect(await connectAndCall({ Origin: 'https://evil.example' })).toEqual({ status: 403 });
    expect(handled).toBe(0);
  });

  it('rejects the null origin by default', async () => {
    await start();
    expect(await connectAndCall({ Origin: 'null' })).toEqual({ status: 403 });
    expect(handled).toBe(0);
  });

  it('accepts non-browser clients that send no Origin', async () => {
    await start();
    const out = await connectAndCall();
    expect(out).toMatchObject({ reply: { id: 1, result: { ok: true } } });
    expect(handled).toBe(1);
  });

  it('accepts an explicitly allowed origin only', async () => {
    await start({ allowedOrigins: ['https://app.example'] });
    expect(await connectAndCall({ Origin: 'https://app.example' })).toMatchObject({ reply: { id: 1 } });
    expect(await connectAndCall({ Origin: 'https://evil.example' })).toEqual({ status: 403 });
    expect(handled).toBe(1);
  });
});

describe('WebSocketTransport bearer token', () => {
  const auth = { enabled: true, method: 'token', tokens: [TOKEN] };

  it('rejects an upgrade with no token', async () => {
    await start({ auth });
    expect(await connectAndCall()).toEqual({ status: 401 });
    expect(handled).toBe(0);
  });

  it('rejects a wrong token', async () => {
    await start({ auth });
    expect(await connectAndCall({ Authorization: 'Bearer wrong-token-wrong-token' })).toEqual({ status: 401 });
    expect(handled).toBe(0);
  });

  it('accepts the configured token', async () => {
    await start({ auth });
    const out = await connectAndCall({ Authorization: `Bearer ${TOKEN}` });
    expect(out).toMatchObject({ reply: { id: 1, result: { ok: true } } });
    expect(handled).toBe(1);
  });

  it('fails closed when auth is enabled with no tokens', async () => {
    await start({ auth: { enabled: true, method: 'token' } });
    expect(await connectAndCall({ Authorization: `Bearer ${TOKEN}` })).toEqual({ status: 401 });
    expect(handled).toBe(0);
  });

  it('still rejects a foreign origin that presents a valid token', async () => {
    await start({ auth });
    expect(await connectAndCall({ Origin: 'https://evil.example', Authorization: `Bearer ${TOKEN}` }))
      .toEqual({ status: 403 });
    expect(handled).toBe(0);
  });
});
