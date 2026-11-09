/**
 * @claude-flow/mcp - Browser origin / Host guards
 *
 * Browsers let any page open a WebSocket to localhost (CORS does not apply to
 * WebSocket upgrades) and DNS rebinding lets a foreign page reach a loopback
 * server under its own hostname. These helpers back the checks that stop a
 * web page from driving a local MCP server.
 */

import type { IncomingMessage } from 'http';

const LOOPBACK_HOST_NAMES = new Set(['localhost', '::1']);

function normalizeHostName(host: string): string {
  return host.trim().toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
}

function isLoopbackName(host: string): boolean {
  const name = normalizeHostName(host);
  return (
    LOOPBACK_HOST_NAMES.has(name) ||
    name.endsWith('.localhost') ||
    /^127(\.\d{1,3}){3}$/.test(name) ||
    /^::ffff:127(\.\d{1,3}){3}$/.test(name)
  );
}

/** True when the server is bound to a loopback interface only. */
export function isLoopbackBindHost(host: string | undefined): boolean {
  return !!host && isLoopbackName(host);
}

/** Hostname part of a Host header value ("[::1]:3000" -> "::1", "a:80" -> "a"). */
function hostHeaderName(hostHeader: string): string {
  const value = hostHeader.trim();
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    return end === -1 ? value : value.slice(0, end + 1);
  }
  const colon = value.lastIndexOf(':');
  return colon === -1 ? value : value.slice(0, colon);
}

/**
 * DNS-rebinding guard. On a loopback bind only loopback Host names (or names
 * listed in `allowedHosts`) are accepted; a request without a Host header is
 * not from a browser and is let through. Non-loopback binds are not checked
 * unless `allowedHosts` is configured.
 */
export function isAllowedHostHeader(
  hostHeader: string | undefined,
  bindHost: string | undefined,
  allowedHosts?: string[]
): boolean {
  if (hostHeader === undefined || hostHeader === '') return true;
  const name = normalizeHostName(hostHeaderName(hostHeader));
  if (allowedHosts?.some((h) => normalizeHostName(h) === name)) return true;
  if (isLoopbackBindHost(bindHost)) return isLoopbackName(name);
  return !allowedHosts || allowedHosts.length === 0;
}

function normalizeOrigin(origin: string): string {
  return origin.trim().toLowerCase().replace(/\/+$/, '');
}

/**
 * Browser-origin allowlist. Requests without an Origin header (CLI clients,
 * curl, server-to-server) are allowed. A present Origin, including the
 * opaque "null", must be listed explicitly. `*` is honoured only when the
 * caller also requires a token, so it can never open an unauthenticated
 * server to every web page.
 */
export function isAllowedOrigin(
  origin: string | undefined,
  allowedOrigins: string[] | undefined,
  authEnabled: boolean
): boolean {
  if (origin === undefined) return true;
  if (!allowedOrigins || allowedOrigins.length === 0) return false;
  const normalized = normalizeOrigin(origin);
  for (const allowed of allowedOrigins) {
    if (allowed === '*') {
      if (authEnabled) return true;
      continue;
    }
    if (normalizeOrigin(allowed) === normalized) return true;
  }
  return false;
}

export interface UpgradeGuardOptions {
  bindHost: string | undefined;
  allowedOrigins?: string[];
  allowedHosts?: string[];
  authEnabled: boolean;
}

/** Reason a WebSocket upgrade must be refused, or undefined when it may proceed. */
export function rejectUpgradeReason(
  req: IncomingMessage,
  options: UpgradeGuardOptions
): 'origin' | 'host' | undefined {
  const origin = req.headers.origin;
  if (!isAllowedOrigin(origin, options.allowedOrigins, options.authEnabled)) return 'origin';
  if (!isAllowedHostHeader(req.headers.host, options.bindHost, options.allowedHosts)) return 'host';
  return undefined;
}
