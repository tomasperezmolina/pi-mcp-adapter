import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authenticate: vi.fn(),
  completeAuthFromInput: vi.fn(),
  startAuth: vi.fn(),
  supportsOAuth: vi.fn(),
  lazyConnect: vi.fn(),
  updateServerMetadata: vi.fn(),
  updateMetadataCache: vi.fn(),
  markKeepAliveAfterConnect: vi.fn(),
  getFailureAgeSeconds: vi.fn(),
  updateStatusBar: vi.fn(),
  clearFailure: vi.fn(),
}));

vi.mock("../mcp-auth-flow.ts", () => ({
  authenticate: mocks.authenticate,
  completeAuthFromInput: mocks.completeAuthFromInput,
  startAuth: mocks.startAuth,
  supportsOAuth: mocks.supportsOAuth,
}));

vi.mock("../init.ts", () => ({
  lazyConnect: mocks.lazyConnect,
  updateServerMetadata: mocks.updateServerMetadata,
  updateMetadataCache: mocks.updateMetadataCache,
  markKeepAliveAfterConnect: mocks.markKeepAliveAfterConnect,
  getFailureAgeSeconds: mocks.getFailureAgeSeconds,
  updateStatusBar: mocks.updateStatusBar,
  clearFailure: mocks.clearFailure,
}));

function createState(overrides: Record<string, unknown> = {}) {
  return {
    config: {
      settings: {},
      mcpServers: {
        demo: { url: "https://api.example.com/mcp", auth: "oauth" },
        bearer: { url: "https://api.example.com/mcp", auth: "bearer" },
      },
    },
    manager: { close: vi.fn(async () => {}) },
    oauthRuntime: { signal: new AbortController().signal },
    toolMetadata: new Map(),
    failureTracker: new Map([["demo", Date.now()]]),
    failureMessages: new Map([["demo", "stale failure"]]),
    ...overrides,
  } as any;
}

describe("manual OAuth proxy actions", () => {
  beforeEach(() => {
    vi.resetModules();
    mocks.authenticate.mockReset().mockResolvedValue("authenticated");
    mocks.completeAuthFromInput.mockReset().mockResolvedValue("authenticated");
    mocks.startAuth.mockReset().mockResolvedValue({
      authorizationUrl: "https://auth.example.com/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A19876%2Fcallback",
    });
    mocks.supportsOAuth.mockReset().mockImplementation((definition) => definition.auth === "oauth");
    mocks.updateStatusBar.mockReset();
    mocks.clearFailure.mockReset().mockImplementation((state: any, serverName: string) => {
      state.failureTracker.delete(serverName);
      state.failureMessages?.delete(serverName);
    });
  });

  it("returns copyable instructions and authorization URL", async () => {
    const { executeAuthStart } = await import("../proxy-modes.ts");
    const state = createState();

    const result = await executeAuthStart(state, "demo");

    expect(mocks.startAuth).toHaveBeenCalledWith(
      "demo",
      "https://api.example.com/mcp",
      state.config.mcpServers.demo,
      { runtime: state.oauthRuntime },
    );
    expect(result.content[0].text).toContain("Open this URL in your local browser");
    expect(result.content[0].text).toContain("https://auth.example.com/authorize");
    expect(result.content[0].text).toContain("auth-complete");
    expect(result.content[0].text).toContain('args: { redirectUrl: "PASTE_REDIRECT_URL_HERE" }');
    expect(result.content[0].text).toContain('args: { code: "PASTE_CODE_HERE" }');
    expect(result.content[0].text).toContain("JSON-string args remain supported");
    expect(result.details).toMatchObject({ mode: "auth-start", server: "demo" });
  });

  it("explains manual completion for pre-registered HTTPS callbacks", async () => {
    mocks.startAuth.mockResolvedValueOnce({
      authorizationUrl: "https://auth.example.com/authorize?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback",
    });
    const { executeAuthStart } = await import("../proxy-modes.ts");

    const result = await executeAuthStart(createState(), "demo");

    expect(result.content[0].text).toContain("pre-registered HTTPS callback");
    expect(result.content[0].text).toContain("even if the destination page reports an error");
    expect(result.content[0].text).toContain("Remote HTTPS callbacks must include the full callback URL");
    expect(result.content[0].text).not.toContain('args: { code: "PASTE_CODE_HERE" }');
    expect(result.content[0].text).not.toContain("redirected localhost URL");
  });

  it("uses the unified interactive flow for auth-start when auto-auth is enabled", async () => {
    const { executeAuthStart } = await import("../proxy-modes.ts");
    const state = createState({
      config: {
        settings: { autoAuth: true, manualOAuthCallbackFallback: false },
        mcpServers: { demo: { url: "https://api.example.com/mcp", auth: "oauth" } },
      },
      ui: { notify: vi.fn(), setStatus: vi.fn(), confirm: vi.fn(), input: vi.fn() },
      openBrowser: vi.fn(),
      copyText: vi.fn(),
      authStorageOptions: {},
    });

    const result = await executeAuthStart(state, "demo");

    expect(mocks.startAuth).not.toHaveBeenCalled();
    expect(mocks.authenticate).toHaveBeenCalledWith(
      "demo",
      "https://api.example.com/mcp",
      state.config.mcpServers.demo,
      expect.objectContaining({
        authStorageOptions: state.authStorageOptions,
        onAuthorizationUrl: expect.any(Function),
        runtime: state.oauthRuntime,
      }),
    );
    expect(mocks.authenticate.mock.calls[0][3].onAuthorizationInput).toBeUndefined();
    expect(state.manager.close).toHaveBeenCalledWith("demo");
    expect(result.content[0].text).toContain("OAuth authentication successful");
    expect(result.details).toMatchObject({ mode: "auth-start", server: "demo", authenticated: true });
  });

  it("propagates cancellation from unified interactive auth-start", async () => {
    const controller = new AbortController();
    mocks.authenticate.mockImplementationOnce(async () => {
      controller.abort();
      throw controller.signal.reason;
    });
    const { executeAuthStart } = await import("../proxy-modes.ts");
    const state = createState({
      config: {
        settings: { autoAuth: true },
        mcpServers: { demo: { url: "https://api.example.com/mcp", auth: "oauth" } },
      },
      ui: { notify: vi.fn(), setStatus: vi.fn(), confirm: vi.fn(), input: vi.fn() },
      openBrowser: vi.fn(),
      copyText: vi.fn(),
    });

    await expect(executeAuthStart(state, "demo", controller.signal)).rejects.toMatchObject({ name: "AbortError" });
  });

  it("rejects auth-start for non-OAuth servers", async () => {
    const { executeAuthStart } = await import("../proxy-modes.ts");

    const result = await executeAuthStart(createState(), "bearer");

    expect(mocks.startAuth).not.toHaveBeenCalled();
    expect(result.content[0].text).toContain("not configured for OAuth");
    expect(result.details).toMatchObject({ error: "oauth_not_supported" });
  });

  it("propagates cancellation from auth-complete", async () => {
    const controller = new AbortController();
    mocks.completeAuthFromInput.mockImplementationOnce(async () => {
      controller.abort();
      throw controller.signal.reason;
    });
    const { executeAuthComplete } = await import("../proxy-modes.ts");

    await expect(
      executeAuthComplete(createState(), "demo", "http://localhost/callback?code=abc&state=state", controller.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("completes auth from a copied redirect URL and resets connection state", async () => {
    const { executeAuthComplete } = await import("../proxy-modes.ts");
    const state = createState();

    const result = await executeAuthComplete(state, "demo", "http://localhost:19876/callback?code=abc&state=state");

    expect(mocks.completeAuthFromInput).toHaveBeenCalledWith(
      "demo",
      "http://localhost:19876/callback?code=abc&state=state",
      { runtime: state.oauthRuntime },
    );
    expect(state.manager.close).toHaveBeenCalledWith("demo");
    expect(state.failureTracker.has("demo")).toBe(false);
    expect(mocks.updateStatusBar).toHaveBeenCalledWith(state);
    expect(result.content[0].text).toContain("OAuth authentication successful");
  });
});
