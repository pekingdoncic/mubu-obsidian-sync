const ALLOWED_AUTH_HOSTS = new Set([
  "open.weixin.qq.com",
  "open.work.weixin.qq.com",
  "graph.qq.com"
]);

export function isAllowedLoginPopupUrl(rawUrl: string): boolean {
  if (rawUrl === "about:blank") return true;

  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") return false;

    const hostname = url.hostname.toLowerCase();
    return hostname === "mubu.com"
      || hostname.endsWith(".mubu.com")
      || ALLOWED_AUTH_HOSTS.has(hostname);
  } catch {
    return false;
  }
}

export function makeBrowserCompatibleUserAgent(userAgent: string): string {
  return userAgent
    .replace(/\s+(?:electron|obsidian)\/[\w.-]+/gi, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

export function safeUrlForLog(rawUrl: string): string {
  if (rawUrl === "about:blank") return rawUrl;

  try {
    const url = new URL(rawUrl);
    return `${url.origin}${url.pathname}`;
  } catch {
    return "[invalid URL]";
  }
}
