#!/usr/bin/env node
'use strict';

const { createRequire } = require('node:module');
const { dirname, join } = require('node:path');

const requireFromHere = createRequire(__filename);

function loadKeyringEntryClass() {
  try {
    return requireFromHere('@napi-rs/keyring').Entry;
  } catch (loaderError) {
    const suffixes = getNativeBindingSuffixes(process.platform, process.arch);
    let lastError;
    for (const suffix of suffixes) {
      try {
        const packageJsonPath = requireFromHere.resolve(`@napi-rs/keyring-${suffix}/package.json`);
        return requireFromHere(join(dirname(packageJsonPath), `keyring.${suffix}.node`)).Entry;
      } catch (error) {
        lastError = error;
      }
    }
    const error = new Error(`Failed to load @napi-rs/keyring in recovery helper: ${lastError?.message ?? loaderError.message}`);
    error.cause = loaderError;
    throw error;
  }
}

function getNativeBindingSuffixes(platform, arch) {
  if (platform === 'linux') {
    if (arch === 'arm64') return ['linux-arm64-gnu', 'linux-arm64-musl'];
    if (arch === 'arm') return ['linux-arm-gnueabihf'];
    if (arch === 'riscv64') return ['linux-riscv64-gnu'];
    if (arch === 'x64') return ['linux-x64-gnu', 'linux-x64-musl'];
  }
  return [];
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => {
      input += chunk;
      if (input.length > 1024 * 1024) {
        reject(new Error('request too large'));
        process.stdin.destroy();
      }
    });
    process.stdin.on('error', reject);
    process.stdin.on('end', () => resolve(input));
  });
}

function writeResponse(response) {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

(async () => {
  try {
    const request = JSON.parse(await readStdin());
    if (!request || typeof request !== 'object') throw new Error('invalid request');
    if (!Array.isArray(request.operations)) throw new Error('invalid operation batch');
    if (request.operations.length === 0) throw new Error('empty operation batch');

    const Entry = loadKeyringEntryClass();
    const results = request.operations.map(({ operation, service, account, payload }) => {
      if (!['read', 'write', 'remove'].includes(operation)) throw new Error('invalid operation');
      if (typeof service !== 'string' || !service) throw new Error('invalid service');
      if (typeof account !== 'string' || !account) throw new Error('invalid account');

      const entry = new Entry(service, account);
      if (operation === 'read') {
        const value = entry.getPassword();
        return value === null ? { found: false } : { found: true, value };
      }
      if (operation === 'write') {
        if (typeof payload !== 'string') throw new Error('invalid payload');
        entry.setPassword(payload);
        return {};
      }

      entry.deleteCredential();
      return {};
    });

    writeResponse({ ok: true, results });
  } catch (error) {
    writeResponse({ ok: false, error: error instanceof Error ? error.message : String(error) });
    process.exitCode = 1;
  }
})();
