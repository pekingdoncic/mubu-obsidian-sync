import { Platform } from "obsidian";
import {
  isAllowedLoginPopupUrl,
  makeBrowserCompatibleUserAgent,
  safeUrlForLog
} from "./auth-policy";

const LOGIN_URL = "https://mubu.com/login";
const SESSION_PARTITION = "persist:mubu-sync";
const LOGIN_POLL_INTERVAL_MS = 1_000;
const LOGIN_TIMEOUT_MS = 5 * 60 * 1_000;

interface ElectronCookie {
  name: string;
  value: string;
}

interface ElectronCookies {
  get(filter: { url?: string; name?: string }): Promise<ElectronCookie[]>;
}

interface ElectronSession {
  cookies: ElectronCookies;
}

interface ElectronWebContents {
  session: ElectronSession;
  getUserAgent(): string;
  setUserAgent(userAgent: string): void;
  setWindowOpenHandler(
    handler: (details: { url: string }) => ElectronWindowOpenResponse
  ): void;
  on(event: "will-navigate" | "will-redirect", listener: (_event: unknown, url: string) => void): void;
  on(event: "did-create-window", listener: (window: ElectronBrowserWindow) => void): void;
}

interface ElectronWindowOpenResponse {
  action: "allow" | "deny";
  overrideBrowserWindowOptions?: Record<string, unknown>;
}

interface ElectronBrowserWindow {
  webContents: ElectronWebContents;
  loadURL(url: string): Promise<void> | void;
  close(): void;
  isDestroyed(): boolean;
  on(event: "closed", listener: () => void): void;
}

interface ElectronBrowserWindowConstructor {
  new(options: Record<string, unknown>): ElectronBrowserWindow;
}

interface ElectronModule {
  BrowserWindow?: ElectronBrowserWindowConstructor;
  remote?: { BrowserWindow?: ElectronBrowserWindowConstructor };
}

type VerifyToken = (token: string) => Promise<void>;

export async function loginToMubu(verifyToken: VerifyToken): Promise<string | null> {
  if (!Platform.isDesktop) {
    throw new Error("幕布自动登录目前仅支持 Obsidian 桌面版");
  }

  const BrowserWindow = resolveBrowserWindow();
  if (!BrowserWindow) {
    throw new Error("当前 Obsidian 无法打开幕布登录窗口，请使用手动 Token 模式");
  }

  return new Promise<string | null>((resolve, reject) => {
    const win = new BrowserWindow({
      width: 480,
      height: 720,
      title: "登录幕布",
      show: true,
      webPreferences: secureWebPreferences()
    });

    let settled = false;
    let checking = false;
    let pollTimer: number | null = null;
    let timeoutTimer: number | null = null;

    const clearTimers = (): void => {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer);
        pollTimer = null;
      }
      if (timeoutTimer !== null) {
        window.clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }
    };

    const finish = (token: string | null): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve(token);
    };

    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      reject(error);
    };

    try {
      configureLoginWindow(win);
    } catch (error) {
      fail(error);
      if (!win.isDestroyed()) win.close();
      return;
    }

    pollTimer = window.setInterval(() => {
      if (checking || settled || win.isDestroyed()) return;
      checking = true;

      void readJwtToken(win.webContents.session)
        .then(async token => {
          if (!token || settled) return;
          await verifyToken(token);
          finish(token);
          if (!win.isDestroyed()) win.close();
        })
        .catch(error => {
          const message = error instanceof Error ? error.message : String(error);
          if (!/token|jwt|登录|认证|401|403/i.test(message)) {
            fail(error);
            if (!win.isDestroyed()) win.close();
          }
        })
        .finally(() => {
          checking = false;
        });
    }, LOGIN_POLL_INTERVAL_MS);

    timeoutTimer = window.setTimeout(() => {
      fail(new Error("幕布登录等待超时，请重试或使用手动 Token 模式"));
      if (!win.isDestroyed()) win.close();
    }, LOGIN_TIMEOUT_MS);

    win.on("closed", () => finish(null));

    let loading: Promise<void> | void;
    try {
      loading = win.loadURL(LOGIN_URL);
    } catch (error) {
      fail(error);
      if (!win.isDestroyed()) win.close();
      return;
    }

    void Promise.resolve(loading).catch(error => {
      fail(error);
      if (!win.isDestroyed()) win.close();
    });
  });
}

function configureLoginWindow(win: ElectronBrowserWindow): void {
  const { webContents } = win;
  const compatibleUserAgent = makeBrowserCompatibleUserAgent(webContents.getUserAgent());
  if (compatibleUserAgent) webContents.setUserAgent(compatibleUserAgent);

  webContents.setWindowOpenHandler(({ url }) => {
    const safeUrl = safeUrlForLog(url);
    if (!isAllowedLoginPopupUrl(url)) {
      console.warn(`[Mubu Sync] Blocked login popup: ${safeUrl}`);
      return { action: "deny" };
    }

    console.debug(`[Mubu Sync] Opening login popup in the Mubu session: ${safeUrl}`);
    return {
      action: "allow",
      overrideBrowserWindowOptions: {
        parent: win,
        show: true,
        webPreferences: secureWebPreferences()
      }
    };
  });

  const logNavigation = (_event: unknown, url: string): void => {
    console.debug(`[Mubu Sync] Login navigation: ${safeUrlForLog(url)}`);
  };
  webContents.on("will-navigate", logNavigation);
  webContents.on("will-redirect", logNavigation);
  webContents.on("did-create-window", childWindow => configureLoginWindow(childWindow));
}

function secureWebPreferences(): Record<string, unknown> {
  return {
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
    partition: SESSION_PARTITION
  };
}

async function readJwtToken(session: ElectronSession): Promise<string | null> {
  const cookies = await session.cookies.get({ url: LOGIN_URL, name: "Jwt-Token" });
  const token = cookies.find(cookie => cookie.name === "Jwt-Token")?.value.trim();
  return token || null;
}

function resolveBrowserWindow(): ElectronBrowserWindowConstructor | null {
  const requireFn = (window as unknown as { require?: (id: string) => unknown }).require;
  if (!requireFn) return null;

  try {
    const electron = requireFn("electron") as ElectronModule;
    if (electron.remote?.BrowserWindow) return electron.remote.BrowserWindow;
    if (electron.BrowserWindow) return electron.BrowserWindow;
  } catch {
    // Try @electron/remote below.
  }

  try {
    const remote = requireFn("@electron/remote") as { BrowserWindow?: ElectronBrowserWindowConstructor };
    return remote.BrowserWindow ?? null;
  } catch {
    return null;
  }
}
