import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createMadaServer } from "./server.mjs";

const password = "Strong-password-42!";
const projectDirectory = fileURLToPath(new URL("../", import.meta.url));

async function makeClient(baseUrl, { origin = baseUrl, defaultHeaders = {} } = {}) {
  const cookies = new Map();
  let csrfToken = "";

  async function request(path, { method = "GET", body, formData, headers = {}, signal } = {}) {
    const requestHeaders = new Headers(defaultHeaders);
    for (const [name, value] of new Headers(headers)) requestHeaders.set(name, value);
    if (!requestHeaders.has("Origin")) requestHeaders.set("Origin", origin);
    const cookieHeader = [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    if (cookieHeader) requestHeaders.set("Cookie", cookieHeader);
    if (!["GET", "HEAD"].includes(method) && !requestHeaders.has("X-CSRF-Token")) {
      requestHeaders.set("X-CSRF-Token", csrfToken);
    }
    if (formData) body = formData;
    else if (body !== undefined) {
      requestHeaders.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }

    const response = await fetch(new URL(path, baseUrl), {
      method,
      headers: requestHeaders,
      body,
      signal,
    });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";", 1);
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator);
      const value = decodeURIComponent(pair.slice(separator + 1));
      if (value) cookies.set(name, value);
      else cookies.delete(name);
    }
    const payload = response.status === 204
      ? null
      : (response.headers.get("Content-Type") || "").includes("application/json")
        ? await response.json()
        : null;
    return { response, payload };
  }

  const csrf = await request("/api/auth/csrf");
  csrfToken = csrf.payload.csrfToken;
  return {
    request,
    async register({ email, username, displayName }) {
      const result = await request("/api/auth/register", {
        method: "POST",
        body: { email, username, displayName, password },
      });
      if (result.payload?.csrfToken) csrfToken = result.payload.csrfToken;
      return result;
    },
    async login(email, loginPassword = password) {
      const result = await request("/api/auth/login", {
        method: "POST",
        body: { email, password: loginPassword },
      });
      if (result.payload?.csrfToken) csrfToken = result.payload.csrfToken;
      return result;
    },
    setCsrfToken(token) { csrfToken = token; },
  };
}

async function createTestServer({
  insideProject = false,
  codespaces = false,
  production = false,
  emailConfiguration = {},
} = {}) {
  const dataDirectory = await mkdtemp(join(insideProject ? projectDirectory : tmpdir(), "mada-api-test-"));
  const environmentKeys = [
    "CODESPACES",
    "MADA_HOST",
    "HOST",
    "MADA_TLS_CERT",
    "MADA_TLS_KEY",
    "NODE_ENV",
    "MADA_RESEND_API_KEY",
    "MADA_EMAIL_FROM",
    "MADA_PUBLIC_URL",
  ];
  const previousEnvironment = new Map(environmentKeys.map((key) => [key, process.env[key]]));
  for (const key of environmentKeys) delete process.env[key];
  if (codespaces) process.env.CODESPACES = "true";
  if (production) process.env.NODE_ENV = "production";
  Object.assign(process.env, emailConfiguration);
  let app;
  try {
    app = await createMadaServer({
      dataDirectory,
      ...(codespaces ? {} : { host: "127.0.0.1" }),
      port: 0,
    });
  } finally {
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  const { address, port } = app.address;
  const connectAddress = address === "0.0.0.0" || address === "::" ? "127.0.0.1" : address;
  return {
    ...app,
    dataDirectory,
    baseUrl: `http://${connectAddress}:${port}`,
    async dispose() {
      await app.close();
      await rm(dataDirectory, { recursive: true, force: true });
    },
  };
}

test("HTTP API enforces authentication and CSRF, persists conversations and messages, and isolates members", async (t) => {
  const app = await createTestServer({ insideProject: true });
  t.after(() => app.dispose());

  const health = await fetch(new URL("/api/health", app.baseUrl));
  assert.deepEqual(await health.json(), { status: "ok", service: "mada", storage: "local-json" });
  const shell = await fetch(new URL("/", app.baseUrl));
  assert.equal(shell.status, 200);
  assert.match(shell.headers.get("content-type"), /text\/html/);
  const clientScript = await fetch(new URL("/app.js", app.baseUrl));
  assert.equal(clientScript.status, 200);
  const serviceWorker = await fetch(new URL("/service-worker.js", app.baseUrl));
  assert.equal(serviceWorker.status, 200);

  const alice = await makeClient(app.baseUrl);
  const unauthenticated = await alice.request("/api/conversations");
  assert.equal(unauthenticated.response.status, 401);
  const staleCsrf = await alice.request("/api/auth/register", {
    method: "POST",
    headers: { "X-CSRF-Token": "invalid" },
    body: { email: "alice@example.test", username: "alice", displayName: "أليس", password },
  });
  assert.equal(staleCsrf.response.status, 403);

  const registeredAlice = await alice.register({
    email: "alice@example.test",
    username: "alice",
    displayName: "أليس",
  });
  assert.equal(registeredAlice.response.status, 201);
  assert.equal(registeredAlice.payload.user.displayName, "أليس");
  assert.equal("passwordHash" in registeredAlice.payload.user, false);
  const privateData = await fetch(new URL(`/${basename(app.dataDirectory)}/mada.json`, app.baseUrl));
  assert.equal(privateData.status, 404);
  const privateSource = await fetch(new URL("/server/server.mjs", app.baseUrl));
  assert.equal(privateSource.status, 404);

  const duplicate = await alice.register({
    email: "alice@example.test",
    username: "alice-new",
    displayName: "حساب آخر",
  });
  assert.equal(duplicate.response.status, 409);

  const bob = await makeClient(app.baseUrl);
  const registeredBob = await bob.register({
    email: "bob@example.test",
    username: "bob",
    displayName: "بُشرى",
  });
  assert.equal(registeredBob.response.status, 201);

  const charlie = await makeClient(app.baseUrl);
  const registeredCharlie = await charlie.register({
    email: "charlie@example.test",
    username: "charlie",
    displayName: "شادي",
  });

  const csrfFailure = await alice.request("/api/conversations", {
    method: "POST",
    headers: { "X-CSRF-Token": "invalid" },
    body: { memberIds: [registeredBob.payload.user.id] },
  });
  assert.equal(csrfFailure.response.status, 403);

  const direct = await alice.request("/api/conversations", {
    method: "POST",
    body: { memberIds: [registeredBob.payload.user.id] },
  });
  assert.equal(direct.response.status, 201);
  assert.equal(direct.payload.conversation.type, "direct");
  const conversationId = direct.payload.conversation.id;

  const existingDirect = await bob.request("/api/conversations", {
    method: "POST",
    body: { memberIds: [registeredAlice.payload.user.id] },
  });
  assert.equal(existingDirect.response.status, 200);
  assert.equal(existingDirect.payload.conversation.id, conversationId);

  const group = await bob.request("/api/conversations", {
    method: "POST",
    body: {
      memberIds: [registeredAlice.payload.user.id, registeredCharlie.payload.user.id],
      name: "رفاق الجامعة",
    },
  });
  assert.equal(group.response.status, 201);
  assert.equal(group.payload.conversation.type, "group");

  const clientMessageId = "d55dfccb-f1e0-4fb7-b3a3-58e3c3f6168d";
  const sent = await bob.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "text", text: "مرحبًا من الخادم", clientMessageId },
  });
  assert.equal(sent.response.status, 201);
  assert.equal(sent.payload.type, "text");
  assert.equal(sent.payload.text, "مرحبًا من الخادم");

  const retry = await bob.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "text", text: "مرحبًا من الخادم", clientMessageId },
  });
  assert.equal(retry.response.status, 200);
  assert.equal(retry.payload.id, sent.payload.id);

  const inbox = await alice.request("/api/conversations?filter=unread");
  assert.equal(inbox.response.status, 200);
  assert.equal(inbox.payload.conversations.length, 1);
  assert.equal(inbox.payload.conversations[0].unreadCount, 1);
  assert.equal(inbox.payload.conversations[0].name, "بُشرى");

  const search = await alice.request("/api/conversations?q=%D9%85%D8%B1%D8%AD%D8%A8%D9%8B%D8%A7");
  assert.equal(search.payload.conversations.length, 1);

  const messages = await alice.request(`/api/conversations/${conversationId}/messages`);
  assert.equal(messages.response.status, 200);
  assert.equal(messages.payload.messages[0].side, "incoming");

  const reader = await alice.request(`/api/conversations/${conversationId}/read`, { method: "POST" });
  assert.equal(reader.response.status, 200);
  const readInbox = await alice.request("/api/conversations?filter=unread");
  assert.equal(readInbox.payload.conversations.length, 0);
  const sentMessages = await bob.request(`/api/conversations/${conversationId}/messages`);
  assert.equal(sentMessages.payload.messages[0].read, true);
  assert.equal(sentMessages.payload.messages[0].conversationId, conversationId);

  const forbiddenRead = await charlie.request(`/api/conversations/${conversationId}/messages`);
  assert.equal(forbiddenRead.response.status, 404);

  const invalidMessage = await bob.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "text", text: " " },
  });
  assert.equal(invalidMessage.response.status, 400);

  const wrongOrigin = await alice.request("/api/auth/logout", {
    method: "POST",
    headers: { Origin: "https://attacker.example" },
    body: {},
  });
  assert.equal(wrongOrigin.response.status, 403);

  const persisted = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  assert.equal(Object.keys(persisted.users).length, 3);
  assert.equal(Object.keys(persisted.messages).length, 1);
});

test("uploads verify content signatures and remain private to conversation members", async (t) => {
  const app = await createTestServer();
  t.after(() => app.dispose());

  const owner = await makeClient(app.baseUrl);
  const ownerResult = await owner.register({ email: "owner@example.test", username: "owner", displayName: "مالك" });
  const member = await makeClient(app.baseUrl);
  const memberResult = await member.register({ email: "member@example.test", username: "member", displayName: "عضو" });
  const outsider = await makeClient(app.baseUrl);
  await outsider.register({ email: "other@example.test", username: "other", displayName: "ضيف" });

  const direct = await owner.request("/api/conversations", {
    method: "POST",
    body: { memberIds: [memberResult.payload.user.id] },
  });
  const conversationId = direct.payload.conversation.id;

  const badImage = new FormData();
  badImage.set("file", new Blob(["not a png"], { type: "image/png" }), "photo.png");
  const rejected = await owner.request(`/api/conversations/${conversationId}/attachments`, {
    method: "POST",
    formData: badImage,
  });
  assert.equal(rejected.response.status, 415);

  const pngBytes = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const image = new FormData();
  image.set("file", new Blob([pngBytes], { type: "image/png" }), "moment.png");
  const uploaded = await owner.request(`/api/conversations/${conversationId}/attachments`, {
    method: "POST",
    formData: image,
  });
  assert.equal(uploaded.response.status, 201);
  assert.equal(uploaded.payload.mimeType, "image/png");

  const moment = await owner.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "moment", attachmentId: uploaded.payload.id, caption: "لحظة تجريبية" },
  });
  assert.equal(moment.response.status, 201);
  assert.equal(moment.payload.type, "moment");
  assert.equal(moment.payload.attachment.url, uploaded.payload.url);

  const hiddenFromOutsider = await outsider.request(uploaded.payload.url);
  assert.equal(hiddenFromOutsider.response.status, 404);
  const availableToMember = await member.request(uploaded.payload.url);
  assert.equal(availableToMember.response.status, 200);
  assert.equal(availableToMember.response.headers.get("Content-Type"), "image/png");

  const wrongAttachmentType = await owner.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "voice", attachmentId: uploaded.payload.id },
  });
  assert.equal(wrongAttachmentType.response.status, 400);

  const card = await member.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: {
      type: "card",
      card: {
        title: "لقاء الخميس",
        location: "مقهى الحي",
        startsAt: "2026-10-01T19:30:00Z",
        description: "لقاء المجموعة",
      },
    },
  });
  assert.equal(card.response.status, 201);
  assert.equal(card.payload.card.location, "مقهى الحي");

  const reaction = await owner.request(`/api/messages/${card.payload.id}/reactions`, {
    method: "POST",
    body: { emoji: "👏" },
  });
  assert.equal(reaction.response.status, 200);
  assert.deepEqual(reaction.payload.reactions["👏"], [ownerResult.payload.user.id]);
});

test("login, health, registration password validation, origin checks, and rate limiting have explicit boundaries", async (t) => {
  const app = await createTestServer();
  t.after(() => app.dispose());

  const client = await makeClient(app.baseUrl);
  const shortPassword = await client.register({
    email: "short@example.test",
    username: "short",
    displayName: "قصير",
  });
  assert.equal(shortPassword.response.status, 201);

  const user = await makeClient(app.baseUrl);
  const registered = await user.register({
    email: "account@example.test",
    username: "account",
    displayName: "حساب",
  });
  assert.equal(registered.response.status, 201);

  const loggedOut = await user.request("/api/auth/logout", { method: "POST", body: {} });
  assert.equal(loggedOut.response.status, 200);
  const invalidLogin = await user.login("account@example.test", "wrong-password-40");
  assert.equal(invalidLogin.response.status, 401);
  const validLogin = await user.login("account@example.test");
  assert.equal(validLogin.response.status, 200);

  const missingOrigin = await user.request("/api/auth/logout", {
    method: "POST",
    headers: { Origin: "https://attacker.invalid" },
    body: {},
  });
  assert.equal(missingOrigin.response.status, 403);

  const rateLimitApp = await createTestServer();
  t.after(() => rateLimitApp.dispose());
  const rateLimitClient = await makeClient(rateLimitApp.baseUrl);
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const invalidPassword = await rateLimitClient.request("/api/auth/register", {
      method: "POST",
      body: { email: "bad@example.test", username: "baduser", displayName: "غير صالح", password: "short" },
    });
    assert.equal(invalidPassword.response.status, 400);
  }
  const rateLimited = await rateLimitClient.request("/api/auth/register", {
    method: "POST",
    body: { email: "bad@example.test", username: "baduser", displayName: "غير صالح", password: "short" },
  });
  assert.equal(rateLimited.response.status, 429);
});

test("live events reach conversation members and persisted accounts survive a server restart", async (t) => {
  const app = await createTestServer();
  let currentServer = app;
  t.after(async () => {
    await currentServer.close();
    await rm(app.dataDirectory, { recursive: true, force: true });
  });

  const alice = await makeClient(app.baseUrl);
  const aliceResult = await alice.register({ email: "stream@example.test", username: "streamer", displayName: "مستمع" });
  const bob = await makeClient(app.baseUrl);
  const bobResult = await bob.register({ email: "writer@example.test", username: "writer", displayName: "كاتب" });
  const direct = await alice.request("/api/conversations", {
    method: "POST",
    body: { memberIds: [bobResult.payload.user.id] },
  });
  const conversationId = direct.payload.conversation.id;

  const abort = new AbortController();
  t.after(() => abort.abort());
  const events = await alice.request("/api/events", { signal: abort.signal });
  assert.equal(events.response.status, 200);
  const reader = events.response.body.getReader();
  t.after(() => reader.cancel().catch(() => {}));
  await reader.read();

  const typing = await bob.request(`/api/conversations/${conversationId}/typing`, {
    method: "POST",
    body: { isTyping: true },
  });
  assert.equal(typing.response.status, 204);
  const typingEvent = await reader.read();
  assert.match(new TextDecoder().decode(typingEvent.value), /event: typing\.updated/);

  const message = await bob.request(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: { type: "text", text: "تحديث مباشر" },
  });
  assert.equal(message.response.status, 201);
  const messageEvent = await reader.read();
  assert.match(new TextDecoder().decode(messageEvent.value), /event: message\.created/);

  await currentServer.close();
  const previousCodespaces = process.env.CODESPACES;
  delete process.env.CODESPACES;
  try {
    currentServer = await createMadaServer({
      dataDirectory: app.dataDirectory,
      host: "127.0.0.1",
      port: 0,
    });
  } finally {
    if (previousCodespaces !== undefined) process.env.CODESPACES = previousCodespaces;
  }
  const restoredAlice = await makeClient(`http://${currentServer.address.address}:${currentServer.address.port}`);
  const loggedIn = await restoredAlice.login("stream@example.test");
  assert.equal(loggedIn.response.status, 200);
  assert.equal(loggedIn.payload.user.id, aliceResult.payload.user.id);
  const restoredInbox = await restoredAlice.request("/api/conversations");
  assert.equal(restoredInbox.payload.conversations.length, 1);
  assert.equal(restoredInbox.payload.conversations[0].preview, "تحديث مباشر");
});

test("server refuses a second writer for the same local data directory", async (t) => {
  const app = await createTestServer();
  t.after(() => app.dispose());
  await assert.rejects(
    createMadaServer({ dataDirectory: app.dataDirectory, host: "127.0.0.1", port: 0 }),
    /already owns/,
  );
});

test("Codespaces accepts only HTTPS proxy headers and applies the external secure origin", async (t) => {
  const app = await createTestServer({ codespaces: true });
  t.after(() => app.dispose());
  assert.equal(app.address.address, "0.0.0.0");

  const proxyHost = "mada-3000.app.github.dev";
  const proxyHeaders = {
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": proxyHost,
  };
  const missingProxyHeaders = await fetch(new URL("/api/health", app.baseUrl));
  assert.equal(missingProxyHeaders.status, 400);
  const insecureProxy = await fetch(new URL("/api/health", app.baseUrl), {
    headers: { ...proxyHeaders, "X-Forwarded-Proto": "http" },
  });
  assert.equal(insecureProxy.status, 400);

  const csrfResponse = await fetch(new URL("/api/auth/csrf", app.baseUrl), { headers: proxyHeaders });
  assert.equal(csrfResponse.status, 200);
  assert.match(csrfResponse.headers.get("strict-transport-security"), /max-age=/);
  assert.match(csrfResponse.headers.get("set-cookie"), /; Secure(?:;|$)/);

  const client = await makeClient(app.baseUrl, {
    origin: `https://${proxyHost}`,
    defaultHeaders: proxyHeaders,
  });
  const registered = await client.register({
    email: "codespaces@example.test",
    username: "codespaces",
    displayName: "مستخدم Codespaces",
  });
  assert.equal(registered.response.status, 201);
  const authCookies = registered.response.headers.getSetCookie();
  assert.equal(authCookies.length, 2);
  assert.ok(authCookies.every((cookie) => /; Secure(?:;|$)/.test(cookie)));

  const wrongOrigin = await client.request("/api/auth/logout", {
    method: "POST",
    headers: { Origin: "https://attacker.example" },
    body: {},
  });
  assert.equal(wrongOrigin.response.status, 403);
});

test("plain HTTP cannot bind a non-local interface outside Codespaces", async () => {
  const environmentKeys = ["CODESPACES", "MADA_TLS_CERT", "MADA_TLS_KEY"];
  const previousEnvironment = new Map(environmentKeys.map((key) => [key, process.env[key]]));
  process.env.CODESPACES = "false";
  delete process.env.MADA_TLS_CERT;
  delete process.env.MADA_TLS_KEY;
  try {
    await assert.rejects(
      createMadaServer({ host: "0.0.0.0", port: 0 }),
      /Bind to loopback for local HTTP/,
    );
  } finally {
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("password reset is generic, CSRF-protected, single-use, and revokes existing sessions", async (t) => {
  const app = await createTestServer();
  t.after(() => app.dispose());
  const owner = await makeClient(app.baseUrl);
  await owner.register({
    email: "reset-owner@example.test",
    username: "resetowner",
    displayName: "مالك الحساب",
  });
  const secondSession = await makeClient(app.baseUrl);
  await secondSession.login("reset-owner@example.test");

  const invalidCsrf = await owner.request("/api/auth/password-reset/request", {
    method: "POST",
    headers: { "X-CSRF-Token": "invalid" },
    body: { email: "reset-owner@example.test" },
  });
  assert.equal(invalidCsrf.response.status, 403);

  const output = [];
  const originalInfo = console.info;
  console.info = (...values) => output.push(values.join(" "));
  let unknown;
  let requested;
  try {
    unknown = await owner.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "missing@example.test" },
    });
    requested = await owner.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "reset-owner@example.test" },
    });
  } finally {
    console.info = originalInfo;
  }
  assert.equal(unknown.response.status, 202);
  assert.deepEqual(unknown.payload, requested.payload);
  assert.equal(requested.response.status, 202);
  assert.equal(output.length, 1);
  assert.match(output[0], /للتطوير المحلي فقط/);

  const resetUrl = new URL(output[0].match(/https?:\/\/\S+/)[0]);
  const token = new URLSearchParams(resetUrl.hash.slice(1)).get("reset");
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(requested.payload).includes(token), false);
  const persisted = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  const [tokenHash] = Object.keys(persisted.passwordResets);
  assert.equal(tokenHash, createHash("sha256").update(token).digest("base64url"));
  assert.equal(JSON.stringify(persisted.passwordResets).includes(token), false);
  assert.equal(persisted.passwordResets[tokenHash].expiresAt - persisted.passwordResets[tokenHash].createdAt, 30 * 60 * 1000);

  const resetCsrfFailure = await owner.request("/api/auth/password-reset/complete", {
    method: "POST",
    headers: { "X-CSRF-Token": "invalid" },
    body: { token, password: "Different-password-52!" },
  });
  assert.equal(resetCsrfFailure.response.status, 403);
  const weakPassword = await owner.request("/api/auth/password-reset/complete", {
    method: "POST",
    body: { token, password: "short" },
  });
  assert.equal(weakPassword.response.status, 400);
  assert.equal(weakPassword.payload.error.code, "INVALID_PASSWORD");

  const changed = await owner.request("/api/auth/password-reset/complete", {
    method: "POST",
    body: { token, password: "Different-password-52!" },
  });
  assert.equal(changed.response.status, 200);
  assert.deepEqual(changed.payload, { ok: true });
  assert.equal((await secondSession.request("/api/auth/me")).response.status, 401);
  const reused = await owner.request("/api/auth/password-reset/complete", {
    method: "POST",
    body: { token, password: "Another-password-53!" },
  });
  assert.equal(reused.response.status, 400);

  const newLogin = await makeClient(app.baseUrl);
  const login = await newLogin.login("reset-owner@example.test", "Different-password-52!");
  assert.equal(login.response.status, 200);
});

test("expired password reset tokens are removed and cannot change the password", async (t) => {
  const app = await createTestServer();
  let currentServer = app;
  t.after(async () => {
    await currentServer.close();
    await rm(app.dataDirectory, { recursive: true, force: true });
  });

  const client = await makeClient(app.baseUrl);
  await client.register({
    email: "expired-reset@example.test",
    username: "expiredreset",
    displayName: "حساب منتهي",
  });
  const output = [];
  const originalInfo = console.info;
  console.info = (...values) => output.push(values.join(" "));
  try {
    await client.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "expired-reset@example.test" },
    });
  } finally {
    console.info = originalInfo;
  }
  const resetUrl = new URL(output[0].match(/https?:\/\/\S+/)[0]);
  const token = new URLSearchParams(resetUrl.hash.slice(1)).get("reset");
  await currentServer.close();

  const statePath = join(app.dataDirectory, "mada.json");
  const state = JSON.parse(await readFile(statePath, "utf8"));
  const [tokenHash] = Object.keys(state.passwordResets);
  state.passwordResets[tokenHash].expiresAt = Date.now() - 1;
  await writeFile(statePath, JSON.stringify(state), "utf8");

  currentServer = await createMadaServer({ dataDirectory: app.dataDirectory, host: "127.0.0.1", port: 0 });
  const restartedUrl = `http://127.0.0.1:${currentServer.address.port}`;
  const restartedClient = await makeClient(restartedUrl);
  const expired = await restartedClient.request("/api/auth/password-reset/complete", {
    method: "POST",
    body: { token, password: "Different-password-54!" },
  });
  assert.equal(expired.response.status, 400);
  const afterExpiry = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(Object.hasOwn(afterExpiry.passwordResets, tokenHash), false);
});

test("password reset reports missing production email configuration without creating a token and rate-limits requests", async (t) => {
  const app = await createTestServer({ production: true });
  t.after(() => app.dispose());
  const client = await makeClient(app.baseUrl);
  await client.register({
    email: "production-reset@example.test",
    username: "productionreset",
    displayName: "مستخدم إنتاج",
  });

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = await client.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "production-reset@example.test" },
    });
    assert.equal(result.response.status, 503);
    assert.match(result.payload.error.message, /MADA_RESEND_API_KEY/);
    assert.equal(JSON.stringify(result.payload).includes("token"), false);
  }
  const limited = await client.request("/api/auth/password-reset/request", {
    method: "POST",
    body: { email: "production-reset@example.test" },
  });
  assert.equal(limited.response.status, 429);
  const state = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  assert.deepEqual(state.passwordResets, {});
});

test("Codespaces password reset fails closed when Resend is not configured", async (t) => {
  const app = await createTestServer({ codespaces: true });
  t.after(() => app.dispose());
  const proxyHost = "mada-3000.app.github.dev";
  const client = await makeClient(app.baseUrl, {
    origin: `https://${proxyHost}`,
    defaultHeaders: {
      "X-Forwarded-Proto": "https",
      "X-Forwarded-Host": proxyHost,
    },
  });
  await client.register({
    email: "configured-later@example.test",
    username: "configuredlater",
    displayName: "مستخدم تجريبي",
  });
  const result = await client.request("/api/auth/password-reset/request", {
    method: "POST",
    body: { email: "configured-later@example.test" },
  });
  assert.equal(result.response.status, 503);
  assert.match(result.payload.error.message, /MADA_RESEND_API_KEY/);
  const state = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  assert.deepEqual(state.passwordResets, {});
  assert.equal(JSON.stringify(result.payload).includes("reset="), false);
});

test("configured password reset sends a Resend email with a fragment link but never returns its token", async (t) => {
  const app = await createTestServer({
    emailConfiguration: {
      MADA_RESEND_API_KEY: "test-resend-key",
      MADA_EMAIL_FROM: "Mada Test <mada@example.test>",
      MADA_PUBLIC_URL: "https://mada.example.test",
    },
  });
  t.after(() => app.dispose());
  const client = await makeClient(app.baseUrl);
  await client.register({
    email: "resend-reset@example.test",
    username: "resendreset",
    displayName: "مستخدم البريد",
  });

  const originalFetch = globalThis.fetch;
  let sentRequest;
  globalThis.fetch = async (input, options) => {
    if (String(input) === "https://api.resend.com/emails") {
      sentRequest = { input: String(input), options };
      return new Response(JSON.stringify({ id: "email-test-id" }), { status: 200 });
    }
    return originalFetch(input, options);
  };
  let result;
  try {
    result = await client.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "resend-reset@example.test" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(result.response.status, 202);
  assert.equal(JSON.stringify(result.payload).includes("reset="), false);
  assert.equal(sentRequest.input, "https://api.resend.com/emails");
  assert.equal(sentRequest.options.headers.Authorization, "Bearer test-resend-key");
  const message = JSON.parse(sentRequest.options.body);
  assert.deepEqual(message.to, ["resend-reset@example.test"]);
  assert.match(message.text, /https:\/\/mada\.example\.test\/#reset=[A-Za-z0-9_-]{43}/);
  assert.match(message.html, /href="https:\/\/mada\.example\.test\/#reset=/);
  const state = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  assert.equal(Object.keys(state.passwordResets).length, 1);
  assert.equal(JSON.stringify(state.passwordResets).includes(message.text.match(/reset=([A-Za-z0-9_-]{43})/)[1]), false);
});

test("failed Resend delivery removes the pending reset token", async (t) => {
  const app = await createTestServer({
    emailConfiguration: {
      MADA_RESEND_API_KEY: "test-resend-key",
      MADA_EMAIL_FROM: "Mada Test <mada@example.test>",
      MADA_PUBLIC_URL: "https://mada.example.test",
    },
  });
  t.after(() => app.dispose());
  const client = await makeClient(app.baseUrl);
  await client.register({
    email: "resend-failure@example.test",
    username: "resendfailure",
    displayName: "فشل الإرسال",
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => {
    if (String(input) === "https://api.resend.com/emails") {
      return new Response("provider unavailable", { status: 503 });
    }
    return originalFetch(input, options);
  };
  let result;
  try {
    result = await client.request("/api/auth/password-reset/request", {
      method: "POST",
      body: { email: "resend-failure@example.test" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(result.response.status, 503);
  assert.equal(JSON.stringify(result.payload).includes("token"), false);
  const state = JSON.parse(await readFile(join(app.dataDirectory, "mada.json"), "utf8"));
  assert.deepEqual(state.passwordResets, {});
});
