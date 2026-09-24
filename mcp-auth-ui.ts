import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AuthenticateOptions } from "./mcp-auth-flow.ts";
import { sanitizeTerminalText } from "./utils.ts";

export const OAUTH_CALLBACK_FALLBACK_DELAY_MS = 10_000;

type InteractiveUi = NonNullable<ExtensionContext["ui"]>;

export interface InteractiveOAuthActions {
  ui: InteractiveUi;
  openBrowser?: (url: string) => Promise<void>;
  copyText?: (text: string) => Promise<void>;
  /** Offer pasted-callback input when automatic localhost callback delivery is unavailable. */
  manualCallbackFallback?: boolean;
}

function terminalHyperlink(label: string, url: string): string {
  return `\u001B]8;;${sanitizeTerminalText(url)}\u001B\\${sanitizeTerminalText(label)}\u001B]8;;\u001B\\`;
}

function waitForFallbackDelay(signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve(true);
    }, OAUTH_CALLBACK_FALLBACK_DELAY_MS);
    timer.unref?.();
    const onAbort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function copyAuthorizationUrl(
  authorizationUrl: string,
  copyText: InteractiveOAuthActions["copyText"],
): Promise<boolean> {
  if (!copyText) return false;
  try {
    await copyText(authorizationUrl);
    return true;
  } catch {
    return false;
  }
}

export function createInteractiveOAuthHandlers(
  serverName: string,
  actions: InteractiveOAuthActions,
): Pick<AuthenticateOptions, "onAuthorizationUrl" | "onAuthorizationInput"> {
  const { ui, openBrowser, copyText } = actions;
  const manualCallbackFallback = actions.manualCallbackFallback !== false;
  let browserOpened = false;
  let authorizationUrlCopied = false;

  const onAuthorizationUrl = async (authorizationUrl: string) => {
    ui.notify(
      `Open this URL to authenticate ${serverName}:\n\n${terminalHyperlink(authorizationUrl, authorizationUrl)}\n\n` +
      (manualCallbackFallback
        ? "After approving, Pi will complete automatically if the browser can reach its localhost callback. " +
          "On a remote machine, copy the full localhost URL from the browser address bar and paste it into Pi."
        : "After approving, Pi will complete automatically through its forwarded localhost callback."),
      "info",
    );
    if (!openBrowser) return false;
    try {
      await openBrowser(authorizationUrl);
      browserOpened = true;
      // Copy while launching rather than during delayed fallback: callback
      // completion can abort the fallback at any time, but clipboard writes
      // are not cancellable once started.
      void copyAuthorizationUrl(authorizationUrl, copyText).then((copied) => {
        authorizationUrlCopied = copied;
      });
      return true;
    } catch (error) {
      let message = `Could not open the OAuth URL automatically: ${error instanceof Error ? error.message : String(error)}`;
      if (copyText) {
        void copyAuthorizationUrl(authorizationUrl, copyText).then((copied) => {
          authorizationUrlCopied = copied;
        });
        message += ". Pi is also attempting to copy the authorization URL to your clipboard.";
      }
      ui.notify(message, "warning");
      // The URL has already been surfaced (and copied when possible), so do
      // not launch a duplicate generic opener. The caller now waits for either
      // its configured manual fallback or the forwarded localhost callback.
      return true;
    }
  };

  if (!manualCallbackFallback) return { onAuthorizationUrl };

  return {
    onAuthorizationUrl,
    onAuthorizationInput: async (authorizationUrl, inputSignal) => {
      if (inputSignal.aborted) return undefined;
      if (browserOpened) {
        const callbackTimedOut = await waitForFallbackDelay(inputSignal);
        if (!callbackTimedOut || inputSignal.aborted) return undefined;
        if (inputSignal.aborted) return undefined;
        ui.notify(
          authorizationUrlCopied
            ? `The OAuth callback for ${serverName} has not arrived. The authorization URL is in your clipboard.`
            : `The OAuth callback for ${serverName} has not arrived. Use the authorization URL shown above.`,
          "warning",
        );
      }

      const readyToPaste = await ui.confirm(
        `Authorize ${serverName}`,
        `Open this link in your browser:\n${terminalHyperlink(authorizationUrl, authorizationUrl)}\n\n` +
        "After approving access, select Yes to paste the callback URL.",
        { signal: inputSignal },
      );
      if (!readyToPaste || inputSignal.aborted) return undefined;
      return ui.input(
        `Complete ${serverName} OAuth`,
        "Paste the full callback URL",
        { signal: inputSignal },
      );
    },
  };
}
