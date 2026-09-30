import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
const appSource = await readFile(new URL("./app.js", import.meta.url), "utf8");
const styles = await readFile(new URL("./styles.css", import.meta.url), "utf8");

function loadAuthFunctions() {
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, { hidden: false, dataset: {}, textContent: "" });
    return elements.get(id);
  };
  const context = {
    document: {
      querySelector(selector) {
        return getElement(selector.slice(1));
      },
    },
    authError: getElement("authError"),
    authNotice: getElement("authNotice"),
    authForm: getElement("authForm"),
  };
  const start = appSource.indexOf("function setAuthMode(mode) {");
  const end = appSource.indexOf("\nfunction showAuthNotice", start);
  assert.notEqual(start, -1, "setAuthMode must exist");
  assert.notEqual(end, -1, "setAuthMode must end before showAuthNotice");
  const modeFunction = appSource.slice(start, end);
  const resetStart = appSource.indexOf("function openPasswordResetForm() {");
  const resetEnd = appSource.indexOf("\nfunction setCurrentUser", resetStart);
  assert.notEqual(resetStart, -1, "openPasswordResetForm must exist");
  assert.notEqual(resetEnd, -1, "openPasswordResetForm must end before setCurrentUser");
  const resetFunction = appSource.slice(resetStart, resetEnd);
  runInNewContext(
    `${modeFunction}\n${resetFunction}\nglobalThis.auth = { setAuthMode, openPasswordResetForm };`,
    context,
  );
  return { elements, auth: context.auth };
}

test("password reset link is visible in registration and login and opens the email request form", async () => {
  const button = html.match(/<button\b[^>]*\bid="authForgotButton"[^>]*>([\s\S]*?)<\/button>/);
  assert.ok(button, "auth dialog contains the forgot-password button");
  assert.match(button[1], /نسيت كلمة المرور؟/);
  assert.doesNotMatch(button[0], /\shidden(?:\s|=|>)/, "forgot-password button must not be hidden in markup");
  const passwordField = html.indexOf('id="authPasswordField"');
  const forgotLink = html.indexOf('id="authForgotButton"');
  assert.ok(passwordField < forgotLink, "forgot-password link follows the password field");
  assert.match(styles, /\.auth-forgot-button\s*\{[^}]*justify-self:\s*start/);
  assert.match(appSource, /#authForgotButton"\)\.addEventListener\("click", openPasswordResetForm\)/);

  const { elements, auth } = loadAuthFunctions();
  auth.setAuthMode("register");
  assert.equal(elements.get("authForgotButton").hidden, false);
  assert.equal(elements.get("authForm").dataset.mode, "register");
  auth.setAuthMode("login");
  assert.equal(elements.get("authForgotButton").hidden, false);
  assert.equal(elements.get("authForm").dataset.mode, "login");

  auth.openPasswordResetForm();
  assert.equal(elements.get("authForgotButton").hidden, false);
  assert.equal(elements.get("authEmailField").hidden, false);
  assert.equal(elements.get("authPasswordField").hidden, true);
  assert.equal(elements.get("authForm").dataset.mode, "forgot");
});
