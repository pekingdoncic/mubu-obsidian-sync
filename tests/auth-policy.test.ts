import assert from "node:assert/strict";
import test from "node:test";
import {
  isAllowedLoginPopupUrl,
  makeBrowserCompatibleUserAgent,
  safeUrlForLog
} from "../src/auth-policy";

test("allows Mubu and supported third-party authentication popups", () => {
  assert.equal(isAllowedLoginPopupUrl("https://mubu.com/login"), true);
  assert.equal(isAllowedLoginPopupUrl("https://api2.mubu.com/auth/callback"), true);
  assert.equal(isAllowedLoginPopupUrl("https://open.weixin.qq.com/connect/qrconnect"), true);
  assert.equal(isAllowedLoginPopupUrl("https://open.work.weixin.qq.com/wwopen/sso/qrConnect"), true);
  assert.equal(isAllowedLoginPopupUrl("https://graph.qq.com/oauth2.0/authorize"), true);
  assert.equal(isAllowedLoginPopupUrl("about:blank"), true);
});

test("rejects insecure, lookalike, custom-protocol, and malformed popup URLs", () => {
  assert.equal(isAllowedLoginPopupUrl("http://mubu.com/login"), false);
  assert.equal(isAllowedLoginPopupUrl("https://mubu.com.example.com/login"), false);
  assert.equal(isAllowedLoginPopupUrl("obsidian://open?vault=test"), false);
  assert.equal(isAllowedLoginPopupUrl("javascript:alert(1)"), false);
  assert.equal(isAllowedLoginPopupUrl("not a URL"), false);
});

test("removes Electron and Obsidian products from the browser user agent", () => {
  const input = "Mozilla/5.0 Chrome/130.0.0.0 Electron/33.0.0 Safari/537.36 obsidian/1.8.0";
  assert.equal(
    makeBrowserCompatibleUserAgent(input),
    "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36"
  );
});

test("redacts authentication query parameters and fragments from logs", () => {
  assert.equal(
    safeUrlForLog("https://mubu.com/auth/callback?code=secret#token=secret"),
    "https://mubu.com/auth/callback"
  );
  assert.equal(safeUrlForLog("about:blank"), "about:blank");
  assert.equal(safeUrlForLog("not a URL"), "[invalid URL]");
});
