import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createReadStream } from "node:fs";
import {
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createHash, pbkdf2, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonStore } from "./store.mjs";

const pbkdf2Async = promisify(pbkdf2);
const projectDirectory = resolve(fileURLToPath(new URL("../", import.meta.url)));
const passwordIterations = 310_000;
const sessionLifetimeMs = 7 * 24 * 60 * 60 * 1000;
const passwordResetLifetimeMs = 30 * 60 * 1000;
const jsonBodyLimit = 1024 * 1024;
const uploadLimit = 12 * 1024 * 1024;
const maximumConversationUploadBytes = 512 * 1024 * 1024;
const maximumServerUploadBytes = 2 * 1024 * 1024 * 1024;
const maximumUsers = 10_000;
const maximumMessages = 100_000;
const messageTypes = new Set(["text", "voice", "moment", "card"]);
const cookieNames = { session: "mada_session", csrf: "mada_csrf" };
const mimeExtensions = new Map([
  ["image/jpeg", ".jpg"],
  ["image/png", ".png"],
  ["image/webp", ".webp"],
  ["audio/webm", ".webm"],
  ["audio/ogg", ".ogg"],
  ["audio/mp4", ".m4a"],
  ["audio/mpeg", ".mp3"],
  ["audio/wav", ".wav"],
]);
const publicMimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".webmanifest", "application/manifest+json"],
  [".webp", "image/webp"],
]);
const publicAssets = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"],
  ["/styles.css", "styles.css"],
  ["/app.js", "app.js"],
  ["/manifest.webmanifest", "manifest.webmanifest"],
  ["/icons/mada.svg", "icons/mada.svg"],
  ["/service-worker.js", "service-worker.js"],
]);
const sessions = new Map();
const eventStreams = new Map();

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const fail = (status, code, message) => {
  throw new ApiError(status, code, message);
};

function normalized(value) {
  return value.normalize("NFC").toLocaleLowerCase("ar").replace(/[\u064b-\u065f\u0670]/g, "");
}

function sendJson(response, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    ...headers,
  });
  response.end(payload);
}

function appendCookies(response, cookies) {
  const existing = response.getHeader("Set-Cookie") || [];
  response.setHeader("Set-Cookie", [...(Array.isArray(existing) ? existing : [existing]), ...cookies]);
}

function parseCookies(request) {
  const result = new Map();
  for (const fragment of (request.headers.cookie || "").split(";")) {
    const index = fragment.indexOf("=");
    if (index < 0) continue;
    try {
      result.set(fragment.slice(0, index).trim(), decodeURIComponent(fragment.slice(index + 1).trim()));
    } catch {
      continue;
    }
  }
  return result;
}

function csrfCookie(value, secure, maxAge = 86_400) {
  return `${cookieNames.csrf}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; SameSite=Strict${secure ? "; Secure" : ""}`;
}

function sessionCookie(value, secure, maxAge = sessionLifetimeMs / 1000) {
  return `${cookieNames.session}=${encodeURIComponent(value)}; Path=/; HttpOnly; Max-Age=${maxAge}; SameSite=Strict${secure ? "; Secure" : ""}`;
}

function applySecurityHeaders(response, secure) {
  response.setHeader("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; style-src 'self'; script-src 'self'");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  if (secure) response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

async function readBytes(request, maximum) {
  const declaredLength = Number(request.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > maximum) fail(413, "BODY_TOO_LARGE", "حجم الطلب أكبر من المسموح.");
  const parts = [];
  let total = 0;
  for await (const part of request) {
    total += part.length;
    if (total > maximum) fail(413, "BODY_TOO_LARGE", "حجم الطلب أكبر من المسموح.");
    parts.push(part);
  }
  return Buffer.concat(parts, total);
}

async function readJson(request) {
  if (!(request.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    fail(415, "UNSUPPORTED_MEDIA_TYPE", "يجب إرسال بيانات JSON.");
  }
  const body = await readBytes(request, jsonBodyLimit);
  try {
    const value = JSON.parse(body.toString("utf8"));
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("Expected an object.");
    return value;
  } catch {
    fail(400, "INVALID_JSON", "تعذّرت قراءة بيانات الطلب.");
  }
}

function checkSameOrigin(request, url, expectedOrigin) {
  const origin = request.headers.origin;
  if (!origin) return;
  if (origin !== expectedOrigin || url.origin !== expectedOrigin) {
    fail(403, "CROSS_ORIGIN_REQUEST", "الطلبات من مصادر مختلفة غير مسموحة.");
  }
}

function codespacesProxyOrigin(request) {
  const protocol = request.headers["x-forwarded-proto"];
  const host = request.headers["x-forwarded-host"];
  if (
    protocol !== "https"
    || typeof host !== "string"
    || host.length > 253
    || !/^[A-Za-z0-9.-]+(?::\d{1,5})?$/.test(host)
  ) {
    return null;
  }
  try {
    const url = new URL(`https://${host}`);
    if (url.host !== host.toLowerCase() || url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function checkedCsrf(request) {
  const cookies = parseCookies(request);
  const cookie = cookies.get(cookieNames.csrf);
  const header = request.headers["x-csrf-token"];
  if (!cookie || typeof header !== "string" || cookie.length !== header.length) {
    fail(403, "CSRF_VALIDATION_FAILED", "انتهت صلاحية الطلب الآمن. حدّث الصفحة وحاول مجددًا.");
  }
  if (!timingSafeEqual(Buffer.from(cookie), Buffer.from(header))) {
    fail(403, "CSRF_VALIDATION_FAILED", "انتهت صلاحية الطلب الآمن. حدّث الصفحة وحاول مجددًا.");
  }
}

function enforceRateLimit(request, scope, rateLimits, maximum = 10) {
  const key = `${scope}:${request.socket.remoteAddress || "unknown"}`;
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || current.resetAt <= now) {
    if (!current && rateLimits.size >= 10_000) {
      for (const [rateKey, entry] of rateLimits) if (entry.resetAt <= now) rateLimits.delete(rateKey);
    }
    if (!current && rateLimits.size >= 10_000) fail(503, "RATE_LIMIT_STORAGE_FULL", "الخادم مشغول. حاول مجددًا بعد قليل.");
    rateLimits.set(key, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return;
  }
  if (current.count >= maximum) fail(429, "RATE_LIMITED", "محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا.");
  current.count += 1;
}

function resetDeliveryConfiguration(expectedOrigin, localDevelopment, settings) {
  const { apiKey, emailFrom, publicUrl } = settings;
  const hasConfiguration = Boolean(apiKey || emailFrom || publicUrl);
  if (!hasConfiguration && localDevelopment) return { mode: "console", publicUrl: expectedOrigin };
  if (!apiKey || !emailFrom || !publicUrl) {
    fail(
      503,
      "PASSWORD_RESET_EMAIL_NOT_CONFIGURED",
      "إعادة تعيين كلمة المرور غير مهيأة: اضبط MADA_RESEND_API_KEY وMADA_EMAIL_FROM وMADA_PUBLIC_URL.",
    );
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(publicUrl);
  } catch {
    fail(503, "PASSWORD_RESET_EMAIL_NOT_CONFIGURED", "قيمة MADA_PUBLIC_URL غير صالحة.");
  }
  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(parsedUrl.hostname);
  const validLocalUrl = localDevelopment && parsedUrl.protocol === "http:" && localHost;
  if (
    (parsedUrl.protocol !== "https:" && !validLocalUrl)
    || parsedUrl.username
    || parsedUrl.password
    || parsedUrl.pathname !== "/"
    || parsedUrl.search
    || parsedUrl.hash
  ) {
    fail(503, "PASSWORD_RESET_EMAIL_NOT_CONFIGURED", "يجب أن يكون MADA_PUBLIC_URL عنوان HTTPS عامًا صالحًا.");
  }
  return { mode: "resend", apiKey, emailFrom, publicUrl: parsedUrl.origin };
}

async function deliverPasswordReset(configuration, email, resetUrl) {
  if (configuration.mode === "console") {
    console.info(`مَدى: رابط استعادة محلي (للتطوير المحلي فقط، لا تشاركه): ${resetUrl}`);
    return;
  }
  let response;
  try {
    response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${configuration.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: configuration.emailFrom,
        to: [email],
        subject: "إعادة تعيين كلمة المرور — مَدى",
        text: `استخدم الرابط التالي لإعادة تعيين كلمة المرور خلال 30 دقيقة:\n${resetUrl}\nإذا لم تطلب ذلك، فتجاهل هذه الرسالة.`,
        html: `<p>استخدم الرابط التالي لإعادة تعيين كلمة المرور خلال 30 دقيقة:</p><p><a href="${resetUrl}">إعادة تعيين كلمة المرور</a></p><p>إذا لم تطلب ذلك، فتجاهل هذه الرسالة.</p>`,
      }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    fail(503, "PASSWORD_RESET_EMAIL_FAILED", "تعذّر إرسال رسالة الاستعادة. حاول مجددًا لاحقًا.");
  }
  if (!response.ok) fail(503, "PASSWORD_RESET_EMAIL_FAILED", "تعذّر إرسال رسالة الاستعادة. تحقق من إعداد البريد ثم حاول مجددًا.");
}

function publicUser(user) {
  return { id: user.id, username: user.username, displayName: user.displayName, createdAt: user.createdAt };
}

function authenticatedUser(request) {
  const sessionId = parseCookies(request).get(cookieNames.session);
  const session = sessionId && sessions.get(sessionId);
  if (!session || session.expiresAt <= Date.now()) {
    if (sessionId) sessions.delete(sessionId);
    fail(401, "AUTHENTICATION_REQUIRED", "سجّل الدخول للمتابعة.");
  }
  return session.userId;
}

function activeConversation(state, conversationId, userId) {
  const conversation = state.conversations[conversationId];
  if (!conversation || !conversation.members.includes(userId)) fail(404, "CONVERSATION_NOT_FOUND", "المحادثة غير موجودة.");
  return conversation;
}

function userUnreadCount(state, conversation, userId) {
  const lastReadAt = conversation.lastReadAt[userId] || "";
  return Object.values(state.messages)
    .filter((message) => message.conversationId === conversation.id && message.authorId !== userId && message.createdAt > lastReadAt)
    .length;
}

function messagePreview(message) {
  if (!message) return "";
  if (message.type === "voice") return "رسالة صوتية";
  if (message.type === "moment") return message.caption || "لحظة";
  if (message.type === "card") return message.card?.title || "بطاقة";
  return message.text;
}

function decorateConversation(state, conversation, userId) {
  const lastMessage = conversation.lastMessageId ? state.messages[conversation.lastMessageId] : null;
  const participants = conversation.members
    .filter((memberId) => memberId !== userId)
    .map((memberId) => state.users[memberId])
    .filter(Boolean)
    .map(publicUser);
  const name = conversation.type === "direct"
    ? participants[0]?.displayName || "محادثة"
    : conversation.name;
  const lastMessageAt = lastMessage?.createdAt || conversation.createdAt;
  return {
    id: conversation.id,
    type: conversation.type,
    name,
    participants,
    preview: messagePreview(lastMessage),
    lastMessageAuthorId: lastMessage?.authorId || null,
    lastMessageAuthorName: lastMessage ? state.users[lastMessage.authorId]?.displayName || null : null,
    lastMessageAt,
    unreadCount: userUnreadCount(state, conversation, userId),
    updatedAt: conversation.updatedAt,
  };
}

function publish(userIds, event, data) {
  const encoded = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const userId of userIds) {
    for (const response of eventStreams.get(userId) || []) {
      if (!response.write(encoded)) response.end();
    }
  }
}

function addEventStream(userId, response) {
  let streams = eventStreams.get(userId);
  if (!streams) eventStreams.set(userId, (streams = new Set()));
  streams.add(response);
  const remove = () => {
    streams.delete(response);
    if (streams.size === 0) eventStreams.delete(userId);
  };
  response.on("close", remove);
  return remove;
}

function requireString(value, field, maximum, { minimum = 1, allowEmpty = false } = {}) {
  if (typeof value !== "string") fail(400, "INVALID_FIELD", `الحقل ${field} غير صالح.`);
  const result = value.trim();
  if ((!allowEmpty && result.length < minimum) || result.length > maximum) {
    fail(400, "INVALID_FIELD", `طول الحقل ${field} غير صالح.`);
  }
  return result;
}

function validatePassword(value) {
  if (typeof value !== "string" || value.length < 12 || value.length > 128) {
    fail(400, "INVALID_PASSWORD", "كلمة المرور مطلوبة وبطول ١٢ إلى ١٢٨ حرفًا.");
  }
  return value;
}

function publicMessage(state, message, userId) {
  const author = state.users[message.authorId];
  const readAt = state.conversations[message.conversationId].lastReadAt;
  const attachment = message.attachmentId ? state.attachments[message.attachmentId] : null;
  return {
    id: message.id,
    clientMessageId: message.clientMessageId,
    conversationId: message.conversationId,
    authorId: message.authorId,
    authorName: author?.displayName || "عضو",
    side: message.authorId === userId ? "outgoing" : "incoming",
    type: message.type,
    text: message.text,
    caption: message.caption,
    card: message.card,
    time: new Intl.DateTimeFormat("ar", { hour: "numeric", minute: "2-digit", timeZone: "UTC" }).format(new Date(message.createdAt)),
    createdAt: message.createdAt,
    read: message.authorId === userId
      ? Object.entries(readAt).some(([memberId, timestamp]) => memberId !== userId && timestamp >= message.createdAt)
      : Boolean(readAt[userId] && readAt[userId] >= message.createdAt),
    attachment: attachment ? {
      id: attachment.id,
      mimeType: attachment.mimeType,
      size: attachment.size,
      url: `/api/attachments/${attachment.id}`,
    } : null,
    reactions: message.reactions || {},
  };
}

function magicMime(buffer, claimedMime) {
  if (claimedMime === "image/jpeg" && buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return ".jpg";
  if (claimedMime === "image/png" && buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return ".png";
  if (claimedMime === "image/webp" && buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return ".webp";
  if (claimedMime === "audio/ogg" && buffer.subarray(0, 4).toString("ascii") === "OggS") return ".ogg";
  if (claimedMime === "audio/webm" && buffer.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return ".webm";
  if (claimedMime === "audio/mp4" && buffer.length >= 12 && buffer.toString("ascii", 4, 8) === "ftyp") return ".m4a";
  if (claimedMime === "audio/mpeg" && (buffer.subarray(0, 3).toString("ascii") === "ID3" || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0))) return ".mp3";
  if (claimedMime === "audio/wav" && buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WAVE") return ".wav";
  return null;
}

function directConversationBetween(state, firstId, secondId) {
  return Object.values(state.conversations).find((conversation) =>
    conversation.type === "direct"
    && conversation.members.length === 2
    && conversation.members.includes(firstId)
    && conversation.members.includes(secondId));
}

function registerSession(response, userId, csrfToken, secure) {
  const sessionId = randomBytes(32).toString("base64url");
  sessions.set(sessionId, { userId, expiresAt: Date.now() + sessionLifetimeMs });
  appendCookies(response, [
    sessionCookie(sessionId, secure),
    csrfCookie(csrfToken, secure),
  ]);
}

export async function createMadaServer({
  dataDirectory = process.env.MADA_DATA_DIR || resolve(projectDirectory, "data"),
  host = process.env.MADA_HOST || (process.env.CODESPACES === "true" ? "0.0.0.0" : process.env.HOST || "127.0.0.1"),
  port = Number(process.env.PORT || 3000),
  tlsCertificateFile = process.env.MADA_TLS_CERT,
  tlsKeyFile = process.env.MADA_TLS_KEY,
} = {}) {
  const trustCodespacesProxy = process.env.CODESPACES === "true";
  const localDevelopment = !trustCodespacesProxy
    && process.env.NODE_ENV !== "production"
    && ["127.0.0.1", "::1", "localhost"].includes(host);
  if (Boolean(tlsCertificateFile) !== Boolean(tlsKeyFile)) {
    throw new Error("Provide both MADA_TLS_CERT and MADA_TLS_KEY to enable HTTPS.");
  }
  if (!tlsCertificateFile && !trustCodespacesProxy && !["127.0.0.1", "::1", "localhost"].includes(host)) {
    throw new Error("Bind to loopback for local HTTP, or configure MADA_TLS_CERT and MADA_TLS_KEY for HTTPS.");
  }
  const tlsOptions = tlsCertificateFile
    ? { cert: await readFile(resolve(tlsCertificateFile)), key: await readFile(resolve(tlsKeyFile)) }
    : null;
  const rateLimits = new Map();
  const store = await new JsonStore(resolve(dataDirectory)).open();
  const resetMailSettings = {
    apiKey: process.env.MADA_RESEND_API_KEY || "",
    emailFrom: process.env.MADA_EMAIL_FROM || "",
    publicUrl: process.env.MADA_PUBLIC_URL || "",
  };

  const handler = async (request, response) => {
    const proxyOrigin = trustCodespacesProxy ? codespacesProxyOrigin(request) : null;
    const secure = trustCodespacesProxy ? Boolean(proxyOrigin) : Boolean(request.socket.encrypted);
    applySecurityHeaders(response, secure);
    if (trustCodespacesProxy && !proxyOrigin) {
      sendJson(response, 400, { error: { code: "INVALID_PROXY_HEADERS", message: "يتطلب الوصول عبر Codespaces اتصال HTTPS موثوقًا." } });
      return;
    }

    let url;
    let expectedOrigin;
    try {
      expectedOrigin = proxyOrigin || new URL(
        `${secure ? "https" : "http"}://${request.headers.host || `${host}:${port}`}`,
      ).origin;
      url = new URL(request.url || "/", expectedOrigin);
    } catch {
      sendJson(response, 400, { error: { code: "INVALID_URL", message: "عنوان الطلب غير صالح." } });
      return;
    }

    try {
      if (request.method === "OPTIONS") {
        response.writeHead(204, { "Allow": "GET, HEAD, POST, OPTIONS" });
        response.end();
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/health") {
        sendJson(response, 200, { status: "ok", service: "mada", storage: "local-json" });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/auth/csrf") {
        const cookies = parseCookies(request);
        const token = cookies.get(cookieNames.csrf) || randomBytes(32).toString("base64url");
        if (!cookies.has(cookieNames.csrf)) appendCookies(response, [csrfCookie(token, secure)]);
        sendJson(response, 200, { csrfToken: token });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/auth/password-reset/request") {
        checkSameOrigin(request, url, expectedOrigin);
        checkedCsrf(request);
        enforceRateLimit(request, "password-reset-ip", rateLimits, 20);
        const body = await readJson(request);
        const email = requireString(body.email, "email", 254).toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, "INVALID_EMAIL", "أدخل بريدًا إلكترونيًا صالحًا.");
        const emailKey = createHash("sha256").update(email).digest("base64url");
        enforceRateLimit(request, `password-reset-email:${emailKey}`, rateLimits, 5);
        const delivery = resetDeliveryConfiguration(expectedOrigin, localDevelopment, resetMailSettings);
        await store.transact((state) => {
          for (const [hash, reset] of Object.entries(state.passwordResets)) {
            if (reset.expiresAt <= Date.now()) delete state.passwordResets[hash];
          }
        });
        const user = store.read((state) => Object.values(state.users).find((entry) => entry.email === email));
        if (user) {
          const token = randomBytes(32).toString("base64url");
          const tokenHash = createHash("sha256").update(token).digest("base64url");
          const createdAt = Date.now();
          await store.transact((state) => {
            for (const [hash, reset] of Object.entries(state.passwordResets)) {
              if (reset.expiresAt <= createdAt || reset.userId === user.id) delete state.passwordResets[hash];
            }
            state.passwordResets[tokenHash] = {
              userId: user.id,
              createdAt,
              expiresAt: createdAt + passwordResetLifetimeMs,
            };
          });

          const resetUrl = new URL("/", delivery.publicUrl);
          resetUrl.hash = new URLSearchParams({ reset: token }).toString();
          try {
            await deliverPasswordReset(delivery, email, resetUrl.href);
          } catch (error) {
            await store.transact((state) => {
              delete state.passwordResets[tokenHash];
            });
            throw error;
          }
        }
        sendJson(response, 202, {
          ok: true,
          message: "إذا كان البريد مرتبطًا بحساب، فستصلك تعليمات الاستعادة.",
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/auth/password-reset/complete") {
        checkSameOrigin(request, url, expectedOrigin);
        checkedCsrf(request);
        enforceRateLimit(request, "password-reset-complete", rateLimits, 10);
        const body = await readJson(request);
        if (typeof body.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.token)) {
          fail(400, "INVALID_PASSWORD_RESET", "رابط الاستعادة غير صالح أو منتهي الصلاحية.");
        }
        const password = validatePassword(body.password);
        const tokenHash = createHash("sha256").update(body.token).digest("base64url");
        const result = await store.transact(async (state) => {
          const reset = state.passwordResets[tokenHash];
          if (!reset || reset.expiresAt <= Date.now()) {
            if (reset) delete state.passwordResets[tokenHash];
            return null;
          }
          const user = state.users[reset.userId];
          if (!user) {
            delete state.passwordResets[tokenHash];
            return null;
          }
          const passwordSalt = randomBytes(16).toString("base64url");
          const passwordHash = await pbkdf2Async(password, Buffer.from(passwordSalt, "base64url"), passwordIterations, 32, "sha256");
          user.passwordSalt = passwordSalt;
          user.passwordHash = passwordHash.toString("base64url");
          for (const [hash, entry] of Object.entries(state.passwordResets)) {
            if (entry.userId === user.id) delete state.passwordResets[hash];
          }
          return user.id;
        });
        if (!result) fail(400, "INVALID_PASSWORD_RESET", "رابط الاستعادة غير صالح أو منتهي الصلاحية.");
        for (const [sessionId, session] of sessions) {
          if (session.userId === result) sessions.delete(sessionId);
        }
        appendCookies(response, [sessionCookie("", secure, 0)]);
        sendJson(response, 200, { ok: true });
        return;
      }

      if (request.method === "POST" && ["/api/auth/register", "/api/auth/login"].includes(url.pathname)) {
        checkSameOrigin(request, url, expectedOrigin);
        checkedCsrf(request);
        enforceRateLimit(request, url.pathname, rateLimits);
        const body = await readJson(request);
        const email = requireString(body.email, "email", 254).toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, "INVALID_EMAIL", "أدخل بريدًا إلكترونيًا صالحًا.");
        const password = validatePassword(body.password);
        let user;

        if (url.pathname.endsWith("/register")) {
          const displayName = requireString(body.displayName, "displayName", 80);
          const username = requireString(body.username || email.split("@")[0], "username", 32, { minimum: 3 }).toLowerCase();
          if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) fail(400, "INVALID_USERNAME", "اسم المستخدم: أحرف لاتينية أو أرقام أو . _ -، بطول 3 إلى 32.");
          const passwordSalt = randomBytes(16).toString("base64url");
          const passwordHash = await pbkdf2Async(password, Buffer.from(passwordSalt, "base64url"), passwordIterations, 32, "sha256");
          user = await store.transact((state) => {
            if (Object.keys(state.users).length >= maximumUsers) fail(503, "REGISTRATION_CLOSED", "التسجيل غير متاح حاليًا.");
            if (Object.values(state.users).some((entry) => entry.email === email || entry.username === username)) {
              fail(409, "ACCOUNT_EXISTS", "البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل.");
            }
            const created = {
              id: randomUUID(),
              email,
              username,
              displayName,
              passwordSalt,
              passwordHash: passwordHash.toString("base64url"),
              createdAt: new Date().toISOString(),
            };
            state.users[created.id] = created;
            return publicUser(created);
          });
        } else {
          user = await store.read((state) => Object.values(state.users).find((entry) => entry.email === email));
          if (!user) {
            await pbkdf2Async(password, Buffer.alloc(16), passwordIterations, 32, "sha256");
            fail(401, "INVALID_CREDENTIALS", "البريد الإلكتروني أو كلمة المرور غير صحيحة.");
          }
          const candidate = await pbkdf2Async(password, Buffer.from(user.passwordSalt, "base64url"), passwordIterations, 32, "sha256");
          const stored = Buffer.from(user.passwordHash, "base64url");
          if (candidate.length !== stored.length || !timingSafeEqual(candidate, stored)) {
            fail(401, "INVALID_CREDENTIALS", "البريد الإلكتروني أو كلمة المرور غير صحيحة.");
          }
          user = publicUser(user);
        }

        const csrfToken = randomBytes(32).toString("base64url");
        registerSession(response, user.id, csrfToken, secure);
        sendJson(response, url.pathname.endsWith("/register") ? 201 : 200, { user, csrfToken });
        return;
      }

      const isMutating = !["GET", "HEAD"].includes(request.method || "");
      if (isMutating) {
        checkSameOrigin(request, url, expectedOrigin);
        checkedCsrf(request);
      }

      if (request.method === "GET" && url.pathname === "/") {
        request.url = "/index.html";
        await servePublicFile(request, response);
        return;
      }

      if (["GET", "HEAD"].includes(request.method || "") && !url.pathname.startsWith("/api/")) {
        await servePublicFile(request, response, url.pathname);
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/auth/me") {
        const userId = authenticatedUser(request);
        const user = store.read((state) => state.users[userId]);
        if (!user) fail(401, "AUTHENTICATION_REQUIRED", "سجّل الدخول للمتابعة.");
        sendJson(response, 200, { user: publicUser(user) });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/auth/logout") {
        const sessionId = parseCookies(request).get(cookieNames.session);
        if (sessionId) sessions.delete(sessionId);
        appendCookies(response, [sessionCookie("", secure, 0)]);
        sendJson(response, 200, { ok: true });
        return;
      }

      const userId = authenticatedUser(request);

      if (request.method === "GET" && url.pathname === "/api/users") {
        const query = normalized(url.searchParams.get("q") || "").trim();
        if (query.length > 100) fail(400, "INVALID_QUERY", "كلمات البحث أطول من المسموح.");
        if (query.length < 2) {
          sendJson(response, 200, { users: [] });
          return;
        }
        const users = store.read((state) => Object.values(state.users)
          .filter((user) => user.id !== userId && `${normalized(user.displayName)} ${user.username}`.includes(query))
          .slice(0, 30)
          .map(publicUser));
        sendJson(response, 200, { users });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/conversations") {
        const query = normalized(url.searchParams.get("q") || "").trim();
        if (query.length > 100) fail(400, "INVALID_QUERY", "كلمات البحث أطول من المسموح.");
        const filter = url.searchParams.get("filter") || "all";
        if (!["all", "unread", "groups"].includes(filter)) fail(400, "INVALID_FILTER", "تصفية المحادثات غير صالحة.");
        const conversations = store.read((state) => Object.values(state.conversations)
          .filter((conversation) => conversation.members.includes(userId))
          .map((conversation) => decorateConversation(state, conversation, userId))
          .filter((conversation) => {
            const matchesQuery = !query || normalized(`${conversation.name} ${conversation.preview} ${conversation.participants.map((participant) => participant.username).join(" ")}`).includes(query);
            const matchesFilter = filter === "all"
              || (filter === "unread" && conversation.unreadCount > 0)
              || (filter === "groups" && conversation.type === "group");
            return matchesQuery && matchesFilter;
          })
          .sort((first, second) => second.lastMessageAt.localeCompare(first.lastMessageAt)));
        sendJson(response, 200, { conversations });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/conversations") {
        const body = await readJson(request);
        if (!Array.isArray(body.memberIds)) fail(400, "INVALID_MEMBERS", "اختر عضوًا واحدًا على الأقل لإنشاء المحادثة.");
        const memberIds = [...new Set(body.memberIds)];
        if (memberIds.length < 1 || memberIds.length > 49 || memberIds.includes(userId)) {
          fail(400, "INVALID_MEMBERS", "اختر عضوًا واحدًا على الأقل لإنشاء المحادثة.");
        }
        const type = memberIds.length === 1 ? "direct" : "group";
        if (body.type && body.type !== type) fail(400, "INVALID_CONVERSATION_TYPE", "نوع المحادثة لا يطابق عدد الأعضاء.");
        const name = type === "group" ? requireString(body.name, "name", 80) : "";
        const result = await store.transact((state) => {
          for (const memberId of memberIds) {
            if (typeof memberId !== "string" || !state.users[memberId]) fail(404, "USER_NOT_FOUND", "أحد الأعضاء غير موجود.");
          }
          if (type === "direct") {
            const existing = directConversationBetween(state, userId, memberIds[0]);
            if (existing) return { conversation: decorateConversation(state, existing, userId), created: false };
          }
          const now = new Date().toISOString();
          const conversation = {
            id: randomUUID(),
            type,
            name,
            members: [userId, ...memberIds],
            createdAt: now,
            updatedAt: now,
            lastMessageId: null,
            lastReadAt: Object.fromEntries([userId, ...memberIds].map((memberId) => [memberId, now])),
          };
          state.conversations[conversation.id] = conversation;
          return { conversation: decorateConversation(state, conversation, userId), created: true };
        });
        if (result.created) publish(result.conversation.participants.map((member) => member.id).concat(userId), "conversation.updated", result.conversation);
        sendJson(response, result.created ? 201 : 200, result);
        return;
      }

      const messagesMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-f-]{36})\/messages$/i);
      if (request.method === "GET" && messagesMatch) {
        const conversationId = messagesMatch[1];
        const query = normalized(url.searchParams.get("q") || "").trim();
        if (query.length > 200) fail(400, "INVALID_QUERY", "كلمات البحث أطول من المسموح.");
        const rawLimit = Number(url.searchParams.get("limit") || 100);
        if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 200) fail(400, "INVALID_LIMIT", "عدد الرسائل المطلوبة غير صالح.");
        const before = url.searchParams.get("before");
        const page = store.read((state) => {
          const conversation = activeConversation(state, conversationId, userId);
          const all = Object.values(state.messages)
            .filter((message) => message.conversationId === conversationId)
            .sort((first, second) => first.createdAt.localeCompare(second.createdAt) || first.id.localeCompare(second.id))
            .filter((message) => !before || message.createdAt < before)
            .filter((message) => !query || normalized(`${message.text || ""} ${message.caption || ""} ${message.card?.title || ""}`).includes(query));
          const messages = all.slice(-rawLimit);
          return {
            conversation: decorateConversation(state, conversation, userId),
            messages: messages.map((message) => publicMessage(state, message, userId)),
            nextBefore: messages.length === rawLimit ? messages[0].createdAt : null,
          };
        });
        sendJson(response, 200, page);
        return;
      }

      const readMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-f-]{36})\/read$/i);
      if (request.method === "POST" && readMatch) {
        const conversationId = readMatch[1];
        const results = await store.transact((state) => {
          const conversation = activeConversation(state, conversationId, userId);
          const previousReadAt = conversation.lastReadAt[userId] || "1970-01-01T00:00:00.000Z";
          const latestMessage = Object.values(state.messages)
            .filter((message) => message.conversationId === conversationId)
            .reduce((latest, message) => Math.max(latest, Date.parse(message.createdAt)), 0);
          const timestamp = new Date(Math.max(Date.now(), latestMessage + 1)).toISOString();
          conversation.lastReadAt[userId] = timestamp;
          conversation.updatedAt = timestamp;
          const conversations = conversation.members.map((memberId) => ({
            userId: memberId,
            conversation: decorateConversation(state, conversation, memberId),
          }));
          const readMessages = Object.values(state.messages)
            .filter((message) => message.conversationId === conversationId
              && message.authorId !== userId
              && message.createdAt > previousReadAt
              && message.createdAt <= timestamp)
            .map((message) => ({
              authorId: message.authorId,
              message: publicMessage(state, message, message.authorId),
            }));
          return { conversations, readMessages };
        });
        for (const result of results.conversations) publish([result.userId], "conversation.updated", result.conversation);
        for (const readMessage of results.readMessages) publish([readMessage.authorId], "message.updated", readMessage.message);
        sendJson(response, 200, results.conversations.find((result) => result.userId === userId).conversation);
        return;
      }

      const typingMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-f-]{36})\/typing$/i);
      if (request.method === "POST" && typingMatch) {
        const body = await readJson(request);
        if (typeof body.isTyping !== "boolean") fail(400, "INVALID_TYPING_STATE", "حالة الكتابة غير صالحة.");
        const conversation = store.read((state) => activeConversation(state, typingMatch[1], userId));
        publish(conversation.members.filter((memberId) => memberId !== userId), "typing.updated", {
          conversationId: conversation.id,
          userId,
          isTyping: body.isTyping,
        });
        response.writeHead(204, { "Cache-Control": "no-store" });
        response.end();
        return;
      }

      if (request.method === "POST" && messagesMatch) {
        const conversationId = messagesMatch[1];
        const body = await readJson(request);
        const type = body.type || "text";
        if (!messageTypes.has(type)) fail(400, "INVALID_MESSAGE_TYPE", "نوع الرسالة غير مدعوم.");
        const text = typeof body.text === "string" ? body.text.trim() : "";
        const caption = typeof body.caption === "string" ? body.caption.trim() : "";
        if (text.length > 2_000 || caption.length > 2_000) fail(400, "MESSAGE_TOO_LONG", "الرسالة أطول من المسموح.");
        if (type === "text" && !text) fail(400, "EMPTY_MESSAGE", "اكتب رسالة قبل الإرسال.");
        const card = type === "card" ? {
          title: requireString(body.card?.title, "card.title", 120),
          location: requireString(body.card?.location, "card.location", 180),
          startsAt: requireString(body.card?.startsAt, "card.startsAt", 40),
          description: typeof body.card?.description === "string" ? body.card.description.trim().slice(0, 500) : "",
        } : null;
        if (type === "card" && !Number.isFinite(Date.parse(card.startsAt))) fail(400, "INVALID_CARD_DATE", "تاريخ البطاقة غير صالح.");
        const clientMessageId = typeof body.clientMessageId === "string" && /^[0-9a-f-]{36}$/i.test(body.clientMessageId)
          ? body.clientMessageId
          : randomUUID();

        const result = await store.transact((state) => {
          const conversation = activeConversation(state, conversationId, userId);
          const existing = Object.values(state.messages).find((message) => message.authorId === userId && message.clientMessageId === clientMessageId);
          if (existing) return { message: publicMessage(state, existing, userId), created: false, members: conversation.members };
          if (Object.keys(state.messages).length >= maximumMessages) fail(503, "MESSAGE_LIMIT_REACHED", "وصلت مساحة الرسائل إلى حدها الحالي.");
          let attachment = null;
          if (type === "voice" || type === "moment") {
            const attachmentId = requireString(body.attachmentId, "attachmentId", 36);
            attachment = state.attachments[attachmentId];
            if (!attachment || attachment.conversationId !== conversationId || attachment.uploaderId !== userId) {
              fail(400, "INVALID_ATTACHMENT", "الملف المرفق غير متاح لهذه المحادثة.");
            }
            if (type === "voice" && !attachment.mimeType.startsWith("audio/")) fail(400, "INVALID_ATTACHMENT_TYPE", "أرفق ملفًا صوتيًا.");
            if (type === "moment" && !attachment.mimeType.startsWith("image/")) fail(400, "INVALID_ATTACHMENT_TYPE", "أرفق صورة للحظة.");
          }
          const timestamp = new Date(Math.max(
            Date.now(),
            Date.parse(conversation.lastReadAt[userId] || "1970-01-01T00:00:00.000Z") + 1,
            Date.parse(conversation.updatedAt) + 1,
          )).toISOString();
          const message = {
            id: randomUUID(),
            clientMessageId,
            conversationId,
            authorId: userId,
            type,
            text,
            caption,
            card,
            attachmentId: attachment?.id || null,
            createdAt: timestamp,
            reactions: {},
          };
          state.messages[message.id] = message;
          conversation.lastMessageId = message.id;
          conversation.updatedAt = timestamp;
          conversation.lastReadAt[userId] = timestamp;
          return { message: publicMessage(state, message, userId), created: true, members: conversation.members };
        });
        if (result.created) publish(result.members, "message.created", result.message);
        sendJson(response, result.created ? 201 : 200, result.message);
        return;
      }

      const reactionMatch = url.pathname.match(/^\/api\/messages\/([0-9a-f-]{36})\/reactions$/i);
      if (request.method === "POST" && reactionMatch) {
        const body = await readJson(request);
        const emoji = requireString(body.emoji, "emoji", 16);
        if (!/^[\p{Extended_Pictographic}\uFE0F\u200D]+$/u.test(emoji)) fail(400, "INVALID_REACTION", "رمز التفاعل غير صالح.");
        const result = await store.transact((state) => {
          const message = state.messages[reactionMatch[1]];
          if (!message) fail(404, "MESSAGE_NOT_FOUND", "الرسالة غير موجودة.");
          const conversation = activeConversation(state, message.conversationId, userId);
          const reactors = message.reactions[emoji] || [];
          message.reactions[emoji] = reactors.includes(userId)
            ? reactors.filter((id) => id !== userId)
            : [...reactors, userId];
          if (message.reactions[emoji].length === 0) delete message.reactions[emoji];
          return { members: conversation.members, message: publicMessage(state, message, userId) };
        });
        publish(result.members, "message.updated", result.message);
        sendJson(response, 200, result.message);
        return;
      }

      const uploadMatch = url.pathname.match(/^\/api\/conversations\/([0-9a-f-]{36})\/attachments$/i);
      if (request.method === "POST" && uploadMatch) {
        store.read((state) => activeConversation(state, uploadMatch[1], userId));
        if (!(request.headers["content-type"] || "").toLowerCase().startsWith("multipart/form-data;")) {
          fail(415, "UNSUPPORTED_MEDIA_TYPE", "ارفع الملف بصيغة multipart/form-data.");
        }
        const requestBytes = await readBytes(request, uploadLimit + 64 * 1024);
        const uploadRequest = new Request("http://mada.local/upload", {
          method: "POST",
          headers: { "Content-Type": request.headers["content-type"] },
          body: requestBytes,
        });
        const form = await uploadRequest.formData();
        const file = form.get("file");
        if (!(file instanceof File)) fail(400, "FILE_REQUIRED", "اختر ملفًا للرفع.");
        if (file.size < 1 || file.size > uploadLimit) fail(413, "FILE_TOO_LARGE", "حجم الملف يجب أن يقل عن ١٢ ميغابايت.");
        const declaredMime = file.type.toLowerCase().split(";", 1)[0].trim();
        if (!mimeExtensions.has(declaredMime)) fail(415, "UNSUPPORTED_FILE_TYPE", "الصور JPEG وPNG وWebP والملفات الصوتية WebM وOGG وMP4 وMP3 فقط.");
        const bytes = Buffer.from(await file.arrayBuffer());
        const extension = magicMime(bytes, declaredMime);
        if (!extension) fail(415, "INVALID_FILE_SIGNATURE", "محتوى الملف لا يطابق نوعه المُعلن.");
        const id = randomUUID();
        const temporaryPath = resolve(store.uploadDirectory, `${id}.tmp`);
        const filePath = resolve(store.uploadDirectory, `${id}${extension}`);
        await mkdir(store.uploadDirectory, { recursive: true });
        await writeFile(temporaryPath, bytes, { flag: "wx", mode: 0o600 });
        try {
          await rename(temporaryPath, filePath);
          const attachment = {
            id,
            conversationId: uploadMatch[1],
            uploaderId: userId,
            filename: `${id}${extension}`,
            mimeType: declaredMime,
            size: bytes.length,
            createdAt: new Date().toISOString(),
          };
          await store.transact((state) => {
            activeConversation(state, uploadMatch[1], userId);
            const conversationBytes = Object.values(state.attachments)
              .filter((item) => item.conversationId === uploadMatch[1])
              .reduce((sum, item) => sum + item.size, 0);
            const serverBytes = Object.values(state.attachments)
              .reduce((sum, item) => sum + item.size, 0);
            if (conversationBytes + bytes.length > maximumConversationUploadBytes
              || serverBytes + bytes.length > maximumServerUploadBytes) {
              fail(413, "STORAGE_LIMIT_REACHED", "وصلت مساحة الملفات إلى حدها الحالي.");
            }
            state.attachments[id] = attachment;
          });
          sendJson(response, 201, {
            id,
            mimeType: attachment.mimeType,
            size: attachment.size,
            url: `/api/attachments/${id}`,
          });
        } catch (error) {
          await rm(temporaryPath, { force: true });
          await rm(filePath, { force: true });
          throw error;
        }
        return;
      }

      const attachmentMatch = url.pathname.match(/^\/api\/attachments\/([0-9a-f-]{36})$/i);
      if (request.method === "GET" && attachmentMatch) {
        const attachment = store.read((state) => {
          const item = state.attachments[attachmentMatch[1]];
          if (!item) fail(404, "ATTACHMENT_NOT_FOUND", "الملف غير موجود.");
          activeConversation(state, item.conversationId, userId);
          return item;
        });
        const filePath = resolve(store.uploadDirectory, attachment.filename);
        if (!filePath.startsWith(`${resolve(store.uploadDirectory)}${sep}`)) fail(404, "ATTACHMENT_NOT_FOUND", "الملف غير موجود.");
        response.writeHead(200, {
          "Cache-Control": "private, no-store",
          "Content-Length": attachment.size,
          "Content-Disposition": `inline; filename="${attachment.filename}"`,
          "Content-Type": attachment.mimeType,
        });
        createReadStream(filePath).on("error", () => response.destroy()).pipe(response);
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/events") {
        authenticatedUser(request);
        response.writeHead(200, {
          "Cache-Control": "no-cache, no-transform",
          "Connection": "keep-alive",
          "Content-Type": "text/event-stream; charset=utf-8",
          "X-Accel-Buffering": "no",
        });
        response.write("retry: 3000\n\n");
        addEventStream(userId, response);
        const heartbeat = setInterval(() => {
          if (!response.write(": heartbeat\n\n")) response.end();
        }, 20_000);
        response.on("close", () => clearInterval(heartbeat));
        return;
      }

      sendJson(response, 404, { error: { code: "NOT_FOUND", message: "المسار غير موجود." } });
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof ApiError) {
        if (error.status === 401) appendCookies(response, [sessionCookie("", secure, 0)]);
        sendJson(response, error.status, { error: { code: error.code, message: error.message } });
        return;
      }
      console.error("Mada request failed:", error);
      sendJson(response, 500, { error: { code: "INTERNAL_ERROR", message: "تعذّر إكمال الطلب. حاول مجددًا." } });
    }
  };
  const server = tlsOptions ? createHttpsServer(tlsOptions, handler) : createHttpServer(handler);

  const close = () => new Promise((resolveClose, rejectClose) => {
    for (const streams of eventStreams.values()) for (const stream of streams) stream.end();
    sessions.clear();
    server.close(async (error) => {
      if (error) {
        rejectClose(error);
        return;
      }
      try {
        await store.close();
        resolveClose();
      } catch (storeError) {
        rejectClose(storeError);
      }
    });
  });

  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  server.maxRequestsPerSocket = 100;
  try {
    server.listen(port, host);
    await new Promise((resolveListen, rejectListen) => {
      server.once("listening", resolveListen);
      server.once("error", rejectListen);
    });
  } catch (error) {
    await store.close();
    throw error;
  }

  return { server, close, address: server.address(), protocol: tlsOptions ? "https" : "http" };
}

async function servePublicFile(request, response, pathname = request.url || "/") {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    fail(400, "INVALID_PATH", "مسار الصفحة غير صالح.");
  }
  if (decoded.includes("\0") || decoded.split("/").includes("..") || decoded.split("/").some((part) => part.startsWith("."))) {
    fail(404, "NOT_FOUND", "الصفحة غير موجودة.");
  }
  const relative = publicAssets.get(decoded);
  if (!relative) fail(404, "NOT_FOUND", "الصفحة غير موجودة.");
  const publicPath = resolve(projectDirectory, relative);
  if (!publicPath.startsWith(`${projectDirectory}${sep}`)) fail(404, "NOT_FOUND", "الصفحة غير موجودة.");
  const mimeType = publicMimeTypes.get(extname(publicPath).toLowerCase());
  if (!mimeType) fail(404, "NOT_FOUND", "الصفحة غير موجودة.");
  let body;
  try {
    body = await readFile(publicPath);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") fail(404, "NOT_FOUND", "الصفحة غير موجودة.");
    throw error;
  }
  response.writeHead(200, {
    "Cache-Control": publicPath.endsWith("index.html") ? "no-cache" : "public, max-age=3600",
    "Content-Length": body.length,
    "Content-Type": mimeType,
  });
  if (request.method === "HEAD") response.end();
  else response.end(body);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { close, address, protocol } = await createMadaServer();
  console.log(`مَدى جاهز على ${protocol}://${address.address}:${address.port}`);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try {
      await close();
      process.exitCode = 0;
    } catch (error) {
      console.error("تعذّر إغلاق مخزن البيانات بأمان:", error);
      process.exitCode = 1;
    }
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
