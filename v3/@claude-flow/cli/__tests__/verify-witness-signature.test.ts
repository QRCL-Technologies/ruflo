/**
 * `ruflo verify` must only accept witness manifests signed by a pinned
 * publisher key. A manifest re-signed with the legacy, publicly derivable
 * seed sha256(gitCommit + ':ruflo-witness/v1') — or with any key embedded
 * in the manifest itself — must fail verification.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import * as ed from '@noble/ed25519';

import { verifyCommand, WITNESS_PUBLIC_KEY_ENV } from '../src/commands/verify.js';
import { output } from '../src/output.js';
import type { CommandContext } from '../src/types.js';

(ed as unknown as { etc: { sha512Sync: (...m: Uint8Array[]) => Uint8Array } }).etc.sha512Sync = (...m) => {
  const h = createHash('sha512');
  for (const x of m) h.update(x);
  return h.digest();
};

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function buildWitness(dir: string, seed: Uint8Array) {
  const fileRel = 'tampered.js';
  const content = 'console.log("mallory"); // FIX_MARKER';
  writeFileSync(join(dir, fileRel), content);
  const manifest = {
    schema: 'ruflo-witness/v1',
    issuedAt: '2026-01-01T00:00:00.000Z',
    gitCommit: 'a'.repeat(40),
    branch: 'main',
    releases: {},
    summary: { totalFixes: 1, verified: 1, failed: 0 },
    fixes: [{
      id: 'F1',
      desc: 'test fix',
      file: fileRel,
      sha256: createHash('sha256').update(content).digest('hex'),
      marker: 'FIX_MARKER',
      markerVerified: true,
    }],
  };
  const manifestHash = createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
  const witness = {
    manifest,
    integrity: {
      manifestHashAlgo: 'sha256',
      manifestHash,
      signatureAlgo: 'ed25519',
      publicKey: hex(ed.getPublicKey(seed)),
      signature: hex(ed.sign(Buffer.from(manifestHash, 'hex'), seed)),
      seedDerivation: "sha256(gitCommit + ':ruflo-witness/v1')",
    },
  };
  const path = join(dir, 'verification.md.json');
  writeFileSync(path, JSON.stringify(witness));
  return { path, manifest };
}

function ctx(flags: Record<string, unknown>): CommandContext {
  return { args: [], flags: { _: [], json: true, ...flags }, cwd: process.cwd(), interactive: false } as unknown as CommandContext;
}

describe('ruflo verify witness signature', () => {
  let dir: string;
  let cwd: string;
  let printed: unknown[];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ruflo-verify-'));
    cwd = process.cwd();
    process.chdir(dir);
    delete process.env[WITNESS_PUBLIC_KEY_ENV];
    printed = [];
    vi.spyOn(output, 'printJson').mockImplementation((v: unknown) => { printed.push(v); });
  });

  afterEach(() => {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
    delete process.env[WITNESS_PUBLIC_KEY_ENV];
    vi.restoreAllMocks();
  });

  it('rejects a manifest re-signed with the gitCommit-derived seed', async () => {
    const forgedSeed = createHash('sha256').update('a'.repeat(40) + ':ruflo-witness/v1').digest();
    const { path } = buildWitness(dir, forgedSeed);

    const res = await verifyCommand.action!(ctx({ manifest: path }));
    expect(res?.success).toBe(false);
    expect((printed[0] as { ok: boolean }).ok).toBe(false);
  });

  it('rejects a self-signed manifest even when a different trusted key is pinned', async () => {
    const attackerSeed = randomBytes(32);
    const { path } = buildWitness(dir, attackerSeed);
    const publisherKey = hex(ed.getPublicKey(randomBytes(32)));

    const res = await verifyCommand.action!(ctx({ manifest: path, publicKey: publisherKey }));
    expect(res?.success).toBe(false);
    expect((printed[0] as { signature: { signatureValid: boolean } }).signature.signatureValid).toBe(false);
  });

  it('accepts a manifest signed by the pinned publisher key', async () => {
    const publisherSeed = randomBytes(32);
    const { path } = buildWitness(dir, publisherSeed);
    process.env[WITNESS_PUBLIC_KEY_ENV] = hex(ed.getPublicKey(publisherSeed));

    const res = await verifyCommand.action!(ctx({ manifest: path }));
    expect(res?.success).toBe(true);
  });

  it('rejects a manifest whose content was edited after signing', async () => {
    const publisherSeed = randomBytes(32);
    const { path, manifest } = buildWitness(dir, publisherSeed);
    const witness = JSON.parse(readFileSync(path, 'utf-8'));
    witness.manifest = { ...manifest, branch: 'evil' };
    witness.integrity.manifestHash = createHash('sha256').update(JSON.stringify(witness.manifest)).digest('hex');
    writeFileSync(path, JSON.stringify(witness));

    const res = await verifyCommand.action!(ctx({ manifest: path, publicKey: hex(ed.getPublicKey(publisherSeed)) }));
    expect(res?.success).toBe(false);
  });
});
