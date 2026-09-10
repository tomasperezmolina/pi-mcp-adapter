import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { tmpdir } from "node:os";
import {
  clearAllCredentials,
  formatOAuthCredentialStoreUnavailable,
  getAuthEntry,
  getAuthEntryFilePath,
  getAuthStorageOptions,
  getTestAuthSecretStoreEntries,
  inspectAuthForUrl,
  OAuthCredentialStoreError,
  removeTestAuthSecretStoreEntry,
  resetAuthEntryCache,
  resetTestAuthSecretStore,
  saveAuthEntry,
} from "../mcp-auth.ts";

/**
 * Windows Credential Manager stores at most CRED_MAX_CREDENTIAL_BLOB_SIZE
 * (2560 bytes) as UTF-16, so a single value cannot exceed 1280 characters.
 */
const AUTH_SECRET_VALUE_LIMIT = 1280;

describe("OAuth credential-store diagnostics", () => {
  it("recognizes a revoked Linux keyring through the error cause chain", () => {
    const nativeError = new Error("Couldn't access platform storage: KeyRevoked", {
      cause: new Error("KeyRevoked"),
    });
    const error = new OAuthCredentialStoreError("read failed", "read", nativeError);

    const message = formatOAuthCredentialStoreUnavailable(error);
    if (process.platform === "linux") {
      expect(message).toContain("Linux session keyring may be revoked");
      expect(message).toContain("fresh login/keyring session");
    } else {
      expect(message).toContain("OAuth credential store unavailable");
    }
  });
});

describe("mcp-auth storage paths", () => {
  const originalEnv = {
    MCP_OAUTH_DIR: process.env.MCP_OAUTH_DIR,
    PI_MCP_ADAPTER_TEST_AUTH_STORE: process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE,
    PI_MCP_ADAPTER_TEST_LINUX_KEYRING_RECOVERY: process.env.PI_MCP_ADAPTER_TEST_LINUX_KEYRING_RECOVERY,
    PI_MCP_ADAPTER_KEYRING_RECOVERY_KEYCTL: process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_KEYCTL,
    PI_MCP_ADAPTER_KEYRING_RECOVERY_NODE: process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_NODE,
    PI_MCP_ADAPTER_KEYRING_RECOVERY_HELPER: process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_HELPER,
    PI_MCP_ADAPTER_FAKE_KEYRING_STORE: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_STORE,
    PI_MCP_ADAPTER_FAKE_KEYRING_REQUESTS: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_REQUESTS,
    PI_MCP_ADAPTER_FAKE_KEYRING_MAX_CHARS: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MAX_CHARS,
    PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_MATCH: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_MATCH,
    PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_NUMBER: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_NUMBER,
    PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_REMOVE_NUMBER: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_REMOVE_NUMBER,
    PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION,
    PI_MCP_ADAPTER_FAKE_KEYRING_MALFORMED_READ: process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MALFORMED_READ,
  };
  let authDir: string;

  beforeEach(() => {
    authDir = mkdtempSync(join(tmpdir(), "pi-mcp-auth-storage-"));
    process.env.MCP_OAUTH_DIR = authDir;
    resetTestAuthSecretStore();
  });

  afterEach(() => {
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    rmSync(authDir, { recursive: true, force: true });
  });

  it("keeps arbitrary configured server names under safe hashed legacy import paths", () => {
    const names = ["Cloudflare Workers", "сервер", "../escape", "@scope/name", ""];

    for (const [index, name] of names.entries()) {
      const token = `token-${index}`;
      saveAuthEntry(name, { tokens: { accessToken: token } }, "https://example.com/mcp");

      expect(getAuthEntry(name)?.tokens?.accessToken).toBe(token);
      const filePath = getAuthEntryFilePath(name);
      const rel = relative(authDir, filePath);
      expect(rel.startsWith("..")).toBe(false);
      expect(isAbsolute(rel)).toBe(false);
      expect(rel).toMatch(/^sha256-[a-f0-9]{64}\/tokens\.json$/);
      expect(existsSync(filePath)).toBe(false);
    }

    expect(existsSync(join(authDir, "..", "escape", "tokens.json"))).toBe(false);
  });

  it("rejects non-string names at the storage boundary", () => {
    expect(() => getAuthEntryFilePath(undefined as unknown as string)).toThrow(/Invalid MCP server name/);
  });

  it("uses configured oauthDir as the legacy import source", () => {
    delete process.env.MCP_OAUTH_DIR;
    const project = mkdtempSync(join(tmpdir(), "pi-mcp-auth-project-"));
    const options = getAuthStorageOptions(".pi/oauth", project);
    const filePath = getAuthEntryFilePath("configured", options);
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify({ tokens: { accessToken: "legacy-token" }, serverUrl: "https://example.com/mcp" }), "utf-8");

    expect(getAuthEntry("configured", options)?.tokens?.accessToken).toBe("legacy-token");
    expect(filePath.startsWith(join(project, ".pi", "oauth"))).toBe(true);
    expect(existsSync(filePath)).toBe(false);
    expect(getAuthEntry("configured", options)?.tokens?.accessToken).toBe("legacy-token");
    rmSync(project, { recursive: true, force: true });
  });

  it("does not migrate legacy credentials during status-only inspection", () => {
    const filePath = getAuthEntryFilePath("status-only");
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify({
      tokens: { accessToken: "legacy-token" },
      serverUrl: "https://example.com/mcp",
    }), "utf-8");

    expect(inspectAuthForUrl("status-only", "https://example.com/mcp").status).toBe("present");
    expect(existsSync(filePath)).toBe(true);

    expect(getAuthEntry("status-only")?.tokens?.accessToken).toBe("legacy-token");
    expect(existsSync(filePath)).toBe(false);
  });

  it("does not use configured oauthDir values as secure-store namespaces", () => {
    delete process.env.MCP_OAUTH_DIR;
    const projectA = mkdtempSync(join(tmpdir(), "pi-mcp-auth-project-a-"));
    const projectB = mkdtempSync(join(tmpdir(), "pi-mcp-auth-project-b-"));
    const optionsA = getAuthStorageOptions(".pi/oauth", projectA);
    const optionsB = getAuthStorageOptions(".pi/oauth", projectB);

    saveAuthEntry("same-server", { tokens: { accessToken: "token-a" } }, "https://example.com/mcp", optionsA);
    saveAuthEntry("same-server", { tokens: { accessToken: "token-b" } }, "https://example.com/mcp", optionsB);

    expect(getAuthEntry("same-server", optionsA)?.tokens?.accessToken).toBe("token-b");
    expect(getAuthEntry("same-server", optionsB)?.tokens?.accessToken).toBe("token-b");
    rmSync(projectA, { recursive: true, force: true });
    rmSync(projectB, { recursive: true, force: true });
  });

  it("keeps MCP_OAUTH_DIR as the explicit override over settings.oauthDir", () => {
    const project = mkdtempSync(join(tmpdir(), "pi-mcp-auth-project-"));
    const options = getAuthStorageOptions(".pi/oauth", project);

    saveAuthEntry("env-override", { tokens: { accessToken: "token" } }, "https://example.com/mcp", options);

    const filePath = getAuthEntryFilePath("env-override", options);
    expect(filePath.startsWith(authDir)).toBe(true);
    expect(filePath.startsWith(join(project, ".pi", "oauth"))).toBe(false);
    rmSync(project, { recursive: true, force: true });
  });

  it("chunks large secure-store entries and reads them back", () => {
    const accessToken = "x".repeat(5000);
    saveAuthEntry("large-entry", { tokens: { accessToken } }, "https://example.com/mcp");

    expect(getAuthEntry("large-entry")?.tokens?.accessToken).toBe(accessToken);
    const entries = getTestAuthSecretStoreEntries();
    const manifestEntry = entries.find(([account]) => !account.includes(".chunk."));
    const chunkEntries = entries.filter(([account]) => account.includes(".chunk."));

    expect(manifestEntry).toBeDefined();
    const manifest = JSON.parse(manifestEntry![1]) as { __piMcpAdapterOAuthChunked?: number; chunkCount?: number };
    expect(manifest.__piMcpAdapterOAuthChunked).toBe(1);
    expect(chunkEntries).toHaveLength(manifest.chunkCount);
    expect(chunkEntries.every(([, payload]) => payload.length <= AUTH_SECRET_VALUE_LIMIT)).toBe(true);
  });

  it("persists records that exceed the strictest per-value store limit", () => {
    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "sizelimited";
    const accessToken = "x".repeat(5000);

    saveAuthEntry("size-limited-large", { tokens: { accessToken } }, "https://example.com/mcp");

    expect(getAuthEntry("size-limited-large")?.tokens?.accessToken).toBe(accessToken);
    expect(getTestAuthSecretStoreEntries().every(([, payload]) => payload.length <= AUTH_SECRET_VALUE_LIMIT)).toBe(true);
  });

  it("persists records just above the per-value limit that are too small for a naive chunk threshold", () => {
    // Regression: a threshold above the store limit skipped chunking entirely,
    // so records in this band failed to persist on Windows at any payload size.
    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "sizelimited";
    const accessToken = "x".repeat(AUTH_SECRET_VALUE_LIMIT + 200);

    saveAuthEntry("size-limited-boundary", { tokens: { accessToken } }, "https://example.com/mcp");

    expect(getAuthEntry("size-limited-boundary")?.tokens?.accessToken).toBe(accessToken);
    expect(getTestAuthSecretStoreEntries().every(([, payload]) => payload.length <= AUTH_SECRET_VALUE_LIMIT)).toBe(true);
  });

  it("keeps small records in a single entry on a size-limited store", () => {
    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "sizelimited";

    saveAuthEntry("size-limited-small", { tokens: { accessToken: "small" } }, "https://example.com/mcp");

    expect(getAuthEntry("size-limited-small")?.tokens?.accessToken).toBe("small");
    const entries = getTestAuthSecretStoreEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0][0]).not.toContain(".chunk.");
  });

  it("clears chunked records written to a size-limited store", () => {
    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "sizelimited";
    saveAuthEntry("size-limited-remove", { tokens: { accessToken: "x".repeat(5000) } }, "https://example.com/mcp");
    expect(getTestAuthSecretStoreEntries().some(([account]) => account.includes(".chunk."))).toBe(true);

    clearAllCredentials("size-limited-remove");

    expect(getTestAuthSecretStoreEntries()).toHaveLength(0);
  });

  it("returns unavailable status when a stored chunk cannot be read", () => {
    saveAuthEntry("large-status", { tokens: { accessToken: "x".repeat(5000) } }, "https://example.com/mcp");
    const chunkAccount = getTestAuthSecretStoreEntries().find(([account]) => account.includes(".chunk."))?.[0];
    expect(chunkAccount).toBeDefined();
    removeTestAuthSecretStoreEntry(chunkAccount!);

    expect(inspectAuthForUrl("large-status", "https://example.com/mcp").status).toBe("unavailable");
  });

  it("removes chunk payloads when credentials are cleared", () => {
    saveAuthEntry("large-remove", { tokens: { accessToken: "x".repeat(5000) } }, "https://example.com/mcp");
    const storedAccounts = getTestAuthSecretStoreEntries().map(([account]) => account);
    expect(storedAccounts.some(account => account.includes(".chunk."))).toBe(true);

    clearAllCredentials("large-remove");

    const remainingAccounts = new Set(getTestAuthSecretStoreEntries().map(([account]) => account));
    expect(storedAccounts.every(account => !remainingAccounts.has(account))).toBe(true);
  });

  it("cleans stale chunks when a large entry is replaced by a small one", () => {
    saveAuthEntry("large-to-small", { tokens: { accessToken: "x".repeat(5000) } }, "https://example.com/mcp");
    expect(getTestAuthSecretStoreEntries().some(([account]) => account.includes(".chunk."))).toBe(true);

    saveAuthEntry("large-to-small", { tokens: { accessToken: "small" } }, "https://example.com/mcp");

    expect(getAuthEntry("large-to-small")?.tokens?.accessToken).toBe("small");
    const entries = getTestAuthSecretStoreEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0][0]).not.toContain(".chunk.");
  });

  it("batches revoked Linux recovery and invalidates cache after ambiguous mutations", () => {
    const harnessDir = mkdtempSync(join(tmpdir(), "pi-mcp-keyring-recovery-"));
    const keyctlPath = join(harnessDir, "keyctl");
    const helperPath = join(harnessDir, "helper.cjs");
    const storePath = join(harnessDir, "store.json");
    const requestsPath = join(harnessDir, "requests.jsonl");

    writeFileSync(keyctlPath, `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != "session" ] || [ "$2" != "pi-mcp-adapter.oauth" ]; then exit 64; fi
shift 2
exec "$@"
`, { mode: 0o755 });
    writeFileSync(helperPath, `const { appendFileSync, existsSync, readFileSync, writeFileSync } = require('node:fs');
const input = JSON.parse(readFileSync(0, 'utf8'));
appendFileSync(process.env.PI_MCP_ADAPTER_FAKE_KEYRING_REQUESTS, JSON.stringify(input) + '\\n');
const path = process.env.PI_MCP_ADAPTER_FAKE_KEYRING_STORE;
const store = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
if (!Array.isArray(input.operations)) throw new Error('invalid operation batch');
let quotaChars = Object.values(store).reduce((total, value) => total + String(value).length, 0);
let writeNumber = 0;
let removeNumber = 0;
let mutationCount = 0;
try {
  const results = input.operations.map(operation => {
    if (operation.operation === 'read') {
      if (process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MALFORMED_READ === '1') return {};
      const value = store[operation.account];
      return value === undefined ? { found: false } : { found: true, value };
    }
    if (operation.operation === 'write') {
      writeNumber++;
      const failMatch = process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_MATCH;
      const failNumber = Number(process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_NUMBER || '0');
      if ((failMatch && operation.payload.includes(failMatch)) || failNumber === writeNumber) {
        throw new Error('injected write failure');
      }
      const maxChars = Number(process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MAX_CHARS || '0');
      quotaChars += operation.payload.length;
      if (maxChars > 0 && quotaChars > maxChars) throw new Error('QuotaExceeded');
      store[operation.account] = operation.payload;
      mutationCount++;
      writeFileSync(path, JSON.stringify(store));
      return {};
    }
    if (operation.operation === 'remove') {
      removeNumber++;
      const failRemoveNumber = Number(process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_REMOVE_NUMBER || '0');
      if (failRemoveNumber === removeNumber) throw new Error('injected remove failure');
      delete store[operation.account];
      mutationCount++;
      writeFileSync(path, JSON.stringify(store));
      return {};
    }
    throw new Error('bad op');
  });
  writeFileSync(path, JSON.stringify(store));
  const responseAfterMutation = mutationCount > 0
    ? process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION
    : undefined;
  if (responseAfterMutation === 'failure') {
    process.stdout.write(JSON.stringify({ ok: false, error: 'injected post-mutation failure' }) + '\\n');
    process.exitCode = 1;
  } else if (responseAfterMutation === 'malformed') {
    process.stdout.write('malformed response\\n');
  } else {
    process.stdout.write(JSON.stringify({ ok: true, results }) + '\\n');
  }
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: error.message }) + '\\n');
  process.exitCode = 1;
}
`);

    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "keyrevoked";
    process.env.PI_MCP_ADAPTER_TEST_LINUX_KEYRING_RECOVERY = "1";
    process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_KEYCTL = keyctlPath;
    process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_NODE = process.execPath;
    process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_HELPER = helperPath;
    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_STORE = storePath;
    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_REQUESTS = requestsPath;
    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MAX_CHARS = "7000";

    const accessToken = "x".repeat(5000);
    const refreshedAccessToken = "y".repeat(5000);
    saveAuthEntry("recovered", { tokens: { accessToken } }, "https://example.com/mcp");
    saveAuthEntry("recovered", { tokens: { accessToken: refreshedAccessToken } }, "https://example.com/mcp");
    resetAuthEntryCache();

    expect(getAuthEntry("recovered")?.tokens?.accessToken).toBe(refreshedAccessToken);

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_NUMBER = "2";
    expect(() => saveAuthEntry("recovered", {
      tokens: { accessToken: "z".repeat(5000) },
    }, "https://example.com/mcp")).toThrow("Failed to write OAuth credentials");
    delete process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_NUMBER;
    // Do not reset the cache: the failed destructive replacement itself must
    // prevent the prior credential from being served as if it were still valid.
    expect(() => getAuthEntry("recovered")).toThrow("Failed to read OAuth credentials");
    const failedReplacementStore = JSON.parse(readFileSync(storePath, "utf8")) as Record<string, string>;
    expect(Object.values(failedReplacementStore).every(stored => !stored.includes("z".repeat(100)))).toBe(true);

    clearAllCredentials("recovered");
    saveAuthEntry("recovered", { tokens: { accessToken: "stable-small" } }, "https://example.com/mcp");

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_MATCH = "pre-mutation-failure";
    expect(() => saveAuthEntry("recovered", {
      tokens: { accessToken: "pre-mutation-failure" },
    }, "https://example.com/mcp")).toThrow("Failed to write OAuth credentials");
    delete process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_WRITE_MATCH;
    expect(getAuthEntry("recovered")?.tokens?.accessToken).toBe("stable-small");

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION = "failure";
    expect(() => saveAuthEntry("recovered", {
      tokens: { accessToken: "persisted-despite-error" },
    }, "https://example.com/mcp")).toThrow("Failed to write OAuth credentials");
    delete process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION;
    expect(getAuthEntry("recovered")?.tokens?.accessToken).toBe("persisted-despite-error");

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION = "malformed";
    expect(() => saveAuthEntry("recovered", {
      tokens: { accessToken: "w".repeat(5000) },
    }, "https://example.com/mcp")).toThrow("Failed to write OAuth credentials");
    delete process.env.PI_MCP_ADAPTER_FAKE_KEYRING_RESPONSE_AFTER_MUTATION;
    expect(() => getAuthEntry("recovered")).toThrow("Failed to read OAuth credentials");

    clearAllCredentials("recovered");
    saveAuthEntry("recovered", { tokens: { accessToken: refreshedAccessToken } }, "https://example.com/mcp");
    expect(getAuthEntry("recovered")?.tokens?.accessToken).toBe(refreshedAccessToken);

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_REMOVE_NUMBER = "2";
    expect(() => clearAllCredentials("recovered")).toThrow("Failed to remove OAuth credentials");
    delete process.env.PI_MCP_ADAPTER_FAKE_KEYRING_FAIL_REMOVE_NUMBER;
    expect(() => getAuthEntry("recovered")).toThrow("Failed to read OAuth credentials");

    clearAllCredentials("recovered");
    expect(getAuthEntry("recovered")).toBeUndefined();
    expect(JSON.parse(readFileSync(storePath, "utf8"))).toEqual({});
    const recoveryRequests = readFileSync(requestsPath, "utf8")
      .trim()
      .split("\n")
      .map(line => JSON.parse(line) as { operations?: Array<{ operation?: string }> });
    expect(recoveryRequests.every(request => Array.isArray(request.operations))).toBe(true);
    expect(recoveryRequests.some(request => request.operations!.filter(operation => operation.operation === "write").length > 1)).toBe(true);
    expect(recoveryRequests.some(request => request.operations!.filter(operation => operation.operation === "read").length > 1)).toBe(true);
    expect(recoveryRequests.some(request => request.operations!.filter(operation => operation.operation === "remove").length > 1)).toBe(true);
    const oldChunkRemovalIndex = recoveryRequests.findIndex(request =>
      request.operations!.length > 1
      && request.operations!.every(operation => operation.operation === "remove"));
    const replacementWriteIndex = recoveryRequests.findIndex((request, index) =>
      index > oldChunkRemovalIndex
      && request.operations!.some(operation => operation.operation === "write"));
    expect(oldChunkRemovalIndex).toBeGreaterThanOrEqual(0);
    expect(replacementWriteIndex).toBeGreaterThan(oldChunkRemovalIndex);
    expect(recoveryRequests[replacementWriteIndex]!.operations!.some(operation => operation.operation === "remove")).toBe(false);

    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_MALFORMED_READ = "1";
    resetAuthEntryCache();
    expect(() => getAuthEntry("malformed-read")).toThrow("Failed to read OAuth credentials");
    rmSync(harnessDir, { recursive: true, force: true });
  });

  it("does not use the recovery helper for generic secure-store failures", () => {
    const harnessDir = mkdtempSync(join(tmpdir(), "pi-mcp-keyring-no-recovery-"));
    const keyctlPath = join(harnessDir, "keyctl");
    const storePath = join(harnessDir, "store.json");
    writeFileSync(keyctlPath, "#!/usr/bin/env bash\nexit 99\n", { mode: 0o755 });

    process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "unavailable";
    process.env.PI_MCP_ADAPTER_TEST_LINUX_KEYRING_RECOVERY = "1";
    process.env.PI_MCP_ADAPTER_KEYRING_RECOVERY_KEYCTL = keyctlPath;
    process.env.PI_MCP_ADAPTER_FAKE_KEYRING_STORE = storePath;

    expect(() => getAuthEntry("generic-unavailable")).toThrow(/OS secure credential store/);
    expect(existsSync(storePath)).toBe(false);
    rmSync(harnessDir, { recursive: true, force: true });
  });
});
