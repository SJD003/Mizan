const workspace = document.querySelector("#workspace");
const connectionStatus = document.querySelector("#connectionStatus");
const connectionLabel = document.querySelector("#connectionLabel");
const profileMenu = document.querySelector("#profileMenu");
const profileButton = document.querySelector("#profileButton");
const profileName = document.querySelector("#profileName");
const profileAvatar = document.querySelector("#profileAvatar");
const profileEmail = document.querySelector("#profileEmail");
const conversationList = document.querySelector("#conversationList");
const emptySearch = document.querySelector("#emptySearch");
const chatTitle = document.querySelector("#chatTitle");
const chatPresence = document.querySelector("#chatPresence");
const chatAvatar = document.querySelector("#chatAvatar");
const introName = document.querySelector("#introName");
const messageList = document.querySelector("#messageList");
const emptyChat = document.querySelector("#emptyChat");
const messageInput = document.querySelector("#messageInput");
const messageForm = document.querySelector("#messageForm");
const sendButton = document.querySelector("#sendButton");
const attachmentInput = document.querySelector("#attachmentInput");
const selectedFileLabel = document.querySelector("#selectedFile");
const recordButton = document.querySelector("#recordButton");
const composerMode = document.querySelector("#composerMode");
const composerModeText = document.querySelector("#composerModeText");
const cardFields = document.querySelector("#cardFields");
const authDialog = document.querySelector("#authDialog");
const authForm = document.querySelector("#authForm");
const authError = document.querySelector("#authError");
const newConversationDialog = document.querySelector("#newConversationDialog");
const newConversationForm = document.querySelector("#newConversationForm");
const userSearchResults = document.querySelector("#userSearchResults");
const conversationError = document.querySelector("#conversationError");
const toast = document.querySelector("#toast");

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

let csrfToken = "";
let currentUser = null;
let conversations = [];
let selectedConversation = null;
let selectedMode = "text";
let selectedMembers = new Set();
let selectedFile = null;
let pendingClientMessageId = null;
let sendingMessage = false;
let activeRecorder = null;
let activeRecordingStream = null;
let recordingParts = [];
let eventStream = null;
let toastTimer;
let conversationSearchTimer;
let messageSearchTimer;
let memberSearchTimer;
let typingTimer;
let lastTypingNotice = 0;
let conversationRequestVersion = 0;
let messageRequestVersion = 0;
let memberRequestVersion = 0;
let nextMessageCursor = null;
let loadingOlderMessages = false;

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function apiUrl(path) {
  return `/api${path}`;
}

async function requestApi(path, { method = "GET", body, formData, signal } = {}) {
  const headers = new Headers({ Accept: "application/json" });
  const options = { method, headers, credentials: "same-origin", signal };
  if (!["GET", "HEAD"].includes(method)) {
    if (!csrfToken) throw new ApiError(0, "MISSING_CSRF_TOKEN", "تعذّر تجهيز طلب آمن. أعد تحميل الصفحة.");
    headers.set("X-CSRF-Token", csrfToken);
  }
  if (formData) options.body = formData;
  else if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(apiUrl(path), options);
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new ApiError(0, "NETWORK_UNAVAILABLE", "تعذّر الاتصال بالخادم. تحقّق من تشغيله واتصال الشبكة.");
  }
  const payload = response.status === 204
    ? null
    : (response.headers.get("Content-Type") || "").includes("application/json")
      ? await response.json()
      : null;

  if (!response.ok) {
    const detail = payload?.error || {};
    const apiError = new ApiError(response.status, detail.code || "REQUEST_FAILED", detail.message || "تعذّر إكمال الطلب.");
    if (response.status === 401 && currentUser) expireSession();
    throw apiError;
  }

  setConnectionStatus(true);
  if (payload?.csrfToken) csrfToken = payload.csrfToken;
  return payload;
}

function setConnectionStatus(connected, message) {
  connectionStatus.classList.toggle("is-connected", connected);
  connectionStatus.classList.toggle("is-error", !connected);
  connectionLabel.textContent = message || (connected ? "الخادم متصل" : "الخادم غير متاح");
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 3500);
}

function showApiError(error) {
  if (error instanceof ApiError && error.status === 401) return;
  if (error.name !== "AbortError") showToast(error.message || "تعذّر إكمال الطلب.");
  if (error instanceof ApiError && error.status === 0) setConnectionStatus(false, "فقدنا الاتصال بالخادم");
}

function safely(action) {
  return (...args) => Promise.resolve(action(...args)).catch(showApiError);
}

function formatNumber(value) {
  return new Intl.NumberFormat("ar-u-nu-arab").format(value);
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "";
  return new Intl.DateTimeFormat("ar", { hour: "numeric", minute: "2-digit" }).format(date);
}

function formatDate(value) {
  return new Intl.DateTimeFormat("ar", { weekday: "long", day: "numeric", month: "long" }).format(new Date(value));
}

function initials(name) {
  return name.trim().slice(0, 1) || "م";
}

function avatarClass(name) {
  let hash = 0;
  for (const character of name) hash = (hash * 31 + character.codePointAt(0)) % 4;
  return `avatar-person-${hash}`;
}

function isGroup(conversation) {
  return conversation?.type === "group";
}

function selectedFilter() {
  return document.querySelector(".filter-button.is-active")?.dataset.filter || "all";
}

function selectedConversationId() {
  return selectedConversation?.id || null;
}

function messageTimeLabel(message) {
  return formatTime(message.createdAt) || message.time || "";
}

function renderConversationItem(conversation) {
  const item = makeElement("button", "conversation-item");
  item.type = "button";
  item.dataset.conversationId = conversation.id;
  if (conversation.id === selectedConversationId()) {
    item.classList.add("is-selected");
    item.setAttribute("aria-current", "true");
  }

  const avatar = makeElement("span", `avatar ${avatarClass(conversation.name)}`, initials(conversation.name));
  avatar.setAttribute("aria-hidden", "true");
  item.append(avatar);

  const copy = makeElement("span", "conversation-copy");
  const top = makeElement("span", "conversation-top");
  top.append(makeElement("strong", "", conversation.name));
  top.append(makeElement("time", "", formatTime(conversation.lastMessageAt) || formatTime(conversation.updatedAt)));

  const bottom = makeElement("span", "conversation-bottom");
  const preview = makeElement("span", "message-preview");
  if (conversation.type === "group" && conversation.lastMessageAuthorName) {
    const author = makeElement("b", "", `${conversation.lastMessageAuthorName}: `);
    preview.append(author, document.createTextNode(conversation.preview || "ابدأوا المحادثة"));
  } else {
    preview.textContent = conversation.preview || "ابدأ المحادثة";
  }
  bottom.append(preview);
  if (conversation.unreadCount > 0) {
    bottom.append(makeElement("span", "unread-count", formatNumber(conversation.unreadCount)));
  } else if (conversation.lastMessageAuthorId === currentUser?.id) {
    bottom.append(makeElement("span", "sent-check", "✓✓"));
  }

  copy.append(top, bottom);
  item.append(copy);
  item.addEventListener("click", safely(() => openConversation(conversation)));
  return item;
}

function renderConversationList() {
  const query = document.querySelector("#chatSearch").value.trim().toLocaleLowerCase("ar");
  const filter = selectedFilter();
  const visible = conversations.filter((conversation) => {
    const text = `${conversation.name} ${conversation.preview || ""} ${conversation.participants.map((participant) => participant.displayName).join(" ")}`;
    return (!query || text.toLocaleLowerCase("ar").includes(query))
      && (filter !== "unread" || conversation.unreadCount > 0)
      && (filter !== "groups" || isGroup(conversation));
  });

  conversationList.replaceChildren(...visible.map(renderConversationItem));
  emptySearch.hidden = visible.length !== 0;
  if (visible.length === 0) {
    if (query) emptySearch.textContent = "ما لقينا محادثة بهذا الاسم.";
    else if (filter === "unread") emptySearch.textContent = "لا توجد محادثات غير مقروءة حاليًا.";
    else if (filter === "groups") emptySearch.textContent = "لا توجد مجموعات بعد.";
    else emptySearch.textContent = "لا توجد محادثات بعد. ابدأ واحدة جديدة.";
  }

  document.querySelector('[data-filter="all"] span').textContent = formatNumber(conversations.length);
  document.querySelector('[data-filter="unread"] span').textContent = formatNumber(conversations.filter((conversation) => conversation.unreadCount > 0).length);
}

async function loadConversations() {
  const version = ++conversationRequestVersion;
  const query = document.querySelector("#chatSearch").value.trim();
  const data = await requestApi(`/conversations${query ? `?q=${encodeURIComponent(query)}` : ""}`);
  if (version !== conversationRequestVersion) return;
  conversations = data.conversations;
  if (selectedConversation) {
    selectedConversation = conversations.find((conversation) => conversation.id === selectedConversation.id) || selectedConversation;
  }
  renderConversationList();
}

function renderVoice(message) {
  const bubble = makeElement("div", "message-bubble voice-message");
  bubble.setAttribute("aria-label", "رسالة صوتية");
  const play = makeElement("button", "voice-play");
  play.type = "button";
  play.setAttribute("aria-label", "تشغيل الرسالة الصوتية");
  play.innerHTML = '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3 1.5v9L10 6 3 1.5Z"/></svg>';
  const wave = makeElement("span", "voice-wave");
  wave.setAttribute("aria-hidden", "true");
  const duration = makeElement("span", "voice-duration", message.attachment?.durationLabel || "صوت");
  bubble.append(play, wave, duration);

  if (message.attachment?.url) {
    const audio = new Audio(message.attachment.url);
    audio.preload = "none";
    play.addEventListener("click", safely(async () => {
      if (audio.paused) await audio.play();
      else audio.pause();
    }));
    audio.addEventListener("play", () => play.setAttribute("aria-label", "إيقاف الرسالة الصوتية"));
    audio.addEventListener("pause", () => play.setAttribute("aria-label", "تشغيل الرسالة الصوتية"));
    audio.addEventListener("ended", () => play.setAttribute("aria-label", "تشغيل الرسالة الصوتية"));
    bubble.append(audio);
  } else {
    play.disabled = true;
    play.setAttribute("aria-label", "لا يتوفر تسجيل صوتي لهذه الرسالة");
  }
  return bubble;
}

function renderMoment(message) {
  const bubble = makeElement("div", "message-bubble moment-card");
  const art = makeElement("div", "moment-art");
  art.setAttribute("role", "img");
  art.setAttribute("aria-label", "صورة لحظة");
  if (message.attachment?.url) {
    const image = makeElement("img");
    image.src = message.attachment.url;
    image.alt = message.caption || "صورة مرفقة";
    image.loading = "lazy";
    art.append(image);
  }
  art.append(makeElement("span", "", "لحظة"));
  bubble.append(art, makeElement("div", "moment-caption", message.caption || ""));
  return bubble;
}

function renderCard(message) {
  const bubble = makeElement("div", "message-bubble contact-card");
  const card = message.card || {};
  const head = makeElement("div", "contact-card-head");
  head.append(makeElement("span", "contact-card-icon", "✳"));
  const title = makeElement("div");
  title.append(makeElement("strong", "", card.title || "بطاقة لقاء"), makeElement("span", "", "دعوة"));
  head.append(title);

  const details = makeElement("div", "contact-card-details");
  if (card.startsAt) details.append(makeElement("span", "", `◷  ${new Intl.DateTimeFormat("ar", { dateStyle: "medium", timeStyle: "short" }).format(new Date(card.startsAt))}`));
  if (card.location) details.append(makeElement("span", "", `⌖  ${card.location}`));
  if (card.description) details.append(makeElement("span", "contact-card-caption", card.description));

  const action = makeElement("button", "contact-card-action", "عرض التفاصيل");
  action.type = "button";
  action.addEventListener("click", () => showToast(`${card.title || "البطاقة"} · ${card.location || "المكان غير محدد"}`));
  bubble.append(head, details, action);
  return bubble;
}

async function addReaction(message, emoji = "❤️") {
  const updated = await requestApi(`/messages/${message.id}/reactions`, {
    method: "POST",
    body: { emoji },
  });
  upsertMessage(updated);
}

function renderReactions(message, row) {
  const reactions = Object.entries(message.reactions || {}).filter(([, members]) => members.length > 0);
  if (reactions.length === 0 && message.side === "outgoing") return;
  const footer = makeElement("div", "message-reactions");
  for (const [emoji, members] of reactions) {
    const button = makeElement("button", "message-reaction", `${emoji} ${formatNumber(members.length)}`);
    button.type = "button";
    button.classList.toggle("is-selected", members.includes(currentUser?.id));
    button.setAttribute("aria-label", `إزالة التفاعل ${emoji}`);
    button.addEventListener("click", safely(() => addReaction(message, emoji)));
    footer.append(button);
  }
  if (message.side === "incoming") {
    const add = makeElement("button", "message-reaction-add", "+");
    add.type = "button";
    add.setAttribute("aria-label", "التفاعل بالحب");
    add.addEventListener("click", safely(() => addReaction(message)));
    footer.append(add);
  }
  row.append(footer);
}

function renderMessage(message) {
  const row = makeElement("article", `message-row is-${message.side}`);
  row.dataset.messageId = message.id;
  const group = isGroup(selectedConversation);
  if (group && message.side === "incoming") row.append(makeElement("span", "message-author", message.authorName));

  if (message.type === "voice") {
    row.append(renderVoice(message));
    if (message.caption) row.append(makeElement("div", "message-caption", message.caption));
  } else if (message.type === "moment") {
    row.append(renderMoment(message));
  } else if (message.type === "card") {
    row.append(renderCard(message));
  } else {
    row.append(makeElement("div", "message-bubble", message.text));
  }

  const meta = makeElement("div", "message-meta");
  const time = makeElement("time", "", messageTimeLabel(message));
  if (message.createdAt) time.dateTime = message.createdAt;
  meta.append(time);
  if (message.side === "outgoing" && message.read) meta.append(makeElement("span", "sent-check", "✓✓"));
  row.append(meta);
  renderReactions(message, row);
  return row;
}

function renderMessages(messages) {
  const visible = messages;
  const children = [];
  let previousDay = "";
  for (const message of visible) {
    const day = new Intl.DateTimeFormat("en-CA").format(new Date(message.createdAt));
    if (day !== previousDay) {
      const divider = makeElement("div", "message-date-divider");
      divider.append(makeElement("span", "", formatDate(message.createdAt)));
      children.push(divider);
      previousDay = day;
    }
    children.push(renderMessage(message));
  }
  messageList.replaceChildren(...children);
  const hasMessages = visible.length > 0;
  emptyChat.hidden = hasMessages;
  if (messageSearchValue()) emptyChat.textContent = "ما لقينا رسالة بهذا البحث.";
  else emptyChat.textContent = "لا توجد رسائل هنا بعد. ابدأ المحادثة برسالة جديدة.";

  document.querySelector("#dateDivider").hidden = true;
  const container = document.querySelector(".chat-content");
  container.scrollTop = container.scrollHeight;
}

function messageSearchValue() {
  return document.querySelector("#messageSearch").value.trim();
}

let currentMessages = [];

function upsertMessage(message) {
  if (message.conversationId !== selectedConversationId()) return;
  const index = currentMessages.findIndex((current) => current.id === message.id);
  if (index < 0) currentMessages.push(message);
  else currentMessages[index] = message;
  currentMessages.sort((first, second) => first.createdAt.localeCompare(second.createdAt));
  renderMessages(currentMessages.filter((item) => {
    const query = messageSearchValue().toLocaleLowerCase("ar");
    const text = `${item.text || ""} ${item.caption || ""} ${item.card?.title || ""} ${item.card?.location || ""}`;
    return !query || text.toLocaleLowerCase("ar").includes(query);
  }));
}

async function fetchMessages(query = "") {
  if (!selectedConversation) return;
  const conversationId = selectedConversation.id;
  const version = ++messageRequestVersion;
  const params = new URLSearchParams();
  params.set("limit", "200");
  if (query) params.set("q", query);
  const result = await requestApi(`/conversations/${conversationId}/messages?${params.toString()}`);
  if (version !== messageRequestVersion || conversationId !== selectedConversationId()) return;
  currentMessages = result.messages;
  nextMessageCursor = result.nextBefore;
  renderMessages(currentMessages);
  selectedConversation = result.conversation;
}

async function loadOlderMessages() {
  if (!selectedConversation || !nextMessageCursor || loadingOlderMessages || messageSearchValue()) return;
  loadingOlderMessages = true;
  const container = document.querySelector(".chat-content");
  const previousHeight = container.scrollHeight;
  const params = new URLSearchParams({ limit: "200", before: nextMessageCursor });
  try {
    const result = await requestApi(`/conversations/${selectedConversation.id}/messages?${params.toString()}`);
    const older = result.messages.filter((message) => !currentMessages.some((existing) => existing.id === message.id));
    currentMessages = [...older, ...currentMessages];
    nextMessageCursor = result.nextBefore;
    renderMessages(currentMessages);
    container.scrollTop += container.scrollHeight - previousHeight;
  } finally {
    loadingOlderMessages = false;
  }
}

function updateChatHeader(conversation) {
  chatTitle.textContent = conversation.name;
  chatAvatar.className = `avatar chat-avatar ${avatarClass(conversation.name)}`;
  chatAvatar.textContent = initials(conversation.name);
  const memberCount = conversation.type === "group" ? conversation.participants.length + 1 : 2;
  chatPresence.textContent = isGroup(conversation)
    ? `مجموعة · ${formatNumber(memberCount)} أعضاء`
    : `@${conversation.participants[0]?.username || "عضو"}`;
  introName.textContent = isGroup(conversation)
    ? conversation.participants.map((participant) => participant.displayName).join("، ")
    : conversation.participants[0]?.displayName || conversation.name;
}

async function openConversation(conversation) {
  selectedConversation = conversation;
  workspace.classList.add("is-chat-open");
  updateChatHeader(conversation);
  document.querySelector("#typingIndicator").hidden = true;
  const latestRead = await requestApi(`/conversations/${conversation.id}/read`, { method: "POST", body: {} });
  selectedConversation = latestRead;
  await Promise.all([loadConversations(), fetchMessages(messageSearchValue())]);
  messageInput.focus({ preventScroll: true });
}

function updateUnreadCounts() {
  document.querySelector('[data-filter="all"] span').textContent = formatNumber(conversations.length);
  document.querySelector('[data-filter="unread"] span').textContent = formatNumber(conversations.filter((conversation) => conversation.unreadCount > 0).length);
}

function showAuthDialog(mode = "register", { allowClose = false } = {}) {
  setAuthMode(mode);
  document.querySelector("#authClose").hidden = !allowClose;
  if (!authDialog.open) authDialog.showModal();
}

function setAuthMode(mode) {
  const registering = mode === "register";
  document.querySelector("#displayNameField").hidden = !registering;
  document.querySelector("#authDisplayName").required = registering;
  document.querySelector("#usernameField").hidden = !registering;
  document.querySelector("#authUsername").required = registering;
  document.querySelector("#authPassword").autocomplete = registering ? "new-password" : "current-password";
  document.querySelector("#authPassword").minLength = registering ? 12 : 1;
  document.querySelector("#authTitle").textContent = registering ? "أنشئ حسابك" : "سجّل الدخول";
  document.querySelector("#authDescription").textContent = registering
    ? "أنشئ حسابًا لمراسلة الأشخاص وحفظ محادثاتك."
    : "سجّل الدخول لمتابعة محادثاتك.";
  document.querySelector("#authSubmit").textContent = registering ? "إنشاء الحساب" : "تسجيل الدخول";
  document.querySelector("#authModeSwitch").textContent = registering ? "لديك حساب؟ سجّل الدخول" : "مستخدم جديد؟ أنشئ حسابًا";
  authError.hidden = true;
  authError.textContent = "";
  authForm.dataset.mode = mode;
}

function setCurrentUser(user) {
  currentUser = user;
  profileName.textContent = user.displayName;
  profileAvatar.textContent = initials(user.displayName);
  profileEmail.textContent = `@${user.username}`;
  profileButton.setAttribute("aria-label", `الملف الشخصي: ${user.displayName}`);
}

function expireSession() {
  currentUser = null;
  workspace.hidden = true;
  closeEventStream();
  setAuthMode("login");
  showAuthDialog("login");
  showToast("انتهت جلسة الدخول. سجّل الدخول مجددًا.");
}

function closeEventStream() {
  eventStream?.close();
  eventStream = null;
}

function subscribeToEvents() {
  closeEventStream();
  eventStream = new EventSource("/api/events");
  eventStream.addEventListener("message.created", safely(async (event) => {
    const message = JSON.parse(event.data);
    if (message.conversationId === selectedConversationId()) {
      upsertMessage(message);
      if (message.authorId !== currentUser.id) {
        selectedConversation = await requestApi(`/conversations/${message.conversationId}/read`, { method: "POST", body: {} });
      }
    }
    await loadConversations();
  }));
  eventStream.addEventListener("message.updated", safely((event) => upsertMessage(JSON.parse(event.data))));
  eventStream.addEventListener("conversation.updated", safely(() => loadConversations()));
  eventStream.addEventListener("typing.updated", (event) => {
    const update = JSON.parse(event.data);
    if (update.conversationId !== selectedConversationId()) return;
    const participant = selectedConversation?.participants.find((item) => item.id === update.userId);
    document.querySelector("#typingLabel").textContent = `${participant?.displayName || "أحد الأعضاء"} يكتب...`;
    document.querySelector("#typingIndicator").hidden = !update.isTyping;
  });
  eventStream.onerror = () => setConnectionStatus(false, "نعيد الاتصال بالخادم...");
  eventStream.onopen = () => setConnectionStatus(true);
}

async function enterWorkspace(user) {
  setCurrentUser(user);
  workspace.hidden = false;
  authDialog.close();
  await loadConversations();
  subscribeToEvents();
  if (conversations.length > 0) {
    const preferred = selectedConversationId()
      ? conversations.find((conversation) => conversation.id === selectedConversationId())
      : conversations[0];
    await openConversation(preferred || conversations[0]);
  } else {
    selectedConversation = null;
    chatTitle.textContent = "ابدأ محادثة";
    introName.textContent = "شخصًا جديدًا";
    chatPresence.textContent = "ابحث عن أعضاء مَدى";
    chatAvatar.className = "avatar chat-avatar avatar-person-2";
    chatAvatar.textContent = "م";
    messageList.replaceChildren();
    currentMessages = [];
    document.querySelector("#dateDivider").hidden = true;
    emptyChat.hidden = false;
    emptyChat.textContent = "ابدأ محادثة جديدة للعثور على أصدقائك.";
  }
}

function refreshConversationsAfterTyping() {
  window.clearTimeout(conversationSearchTimer);
  conversationSearchTimer = window.setTimeout(safely(loadConversations), 180);
}

function selectMode(mode) {
  if (activeRecorder?.state === "recording" && mode !== "voice") {
    showToast("أوقف التسجيل قبل تغيير نوع الرسالة.");
    return;
  }
  selectedMode = mode;
  for (const button of document.querySelectorAll(".tool-button")) {
    const active = button.dataset.mode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  }
  composerMode.hidden = mode === "text";
  cardFields.hidden = mode !== "card";
  recordButton.hidden = mode !== "voice";
  const descriptions = {
    voice: "سجّل مقطعًا صوتيًا أو أرفق ملفًا صوتيًا.",
    moment: "أرفق صورة لمشاركتها كلحظة.",
    card: "أنشئ بطاقة لقاء باسم ومكان وموعد.",
  };
  composerModeText.textContent = descriptions[mode] || "";
  messageInput.placeholder = mode === "text"
    ? "اكتب رسالة..."
    : mode === "voice"
      ? "أضف تعليقًا على التسجيل (اختياري)..."
      : mode === "moment"
        ? "أضف تعليقًا للصورة (اختياري)..."
        : "أضف وصفًا (اختياري)...";
  if (selectedFile && !fileMatchesMode(selectedFile, mode)) setSelectedFile(null);
  attachmentInput.accept = mode === "voice"
    ? "audio/webm,audio/ogg,audio/mp4,audio/mpeg,audio/wav"
    : "image/jpeg,image/png,image/webp";
  updateSendButton();
}

function fileMatchesMode(file, mode) {
  return (mode === "voice" && file.type.startsWith("audio/"))
    || (mode === "moment" && file.type.startsWith("image/"));
}

function setSelectedFile(file) {
  selectedFile = file;
  selectedFileLabel.hidden = !file;
  selectedFileLabel.textContent = file ? file.name : "";
  updateSendButton();
}

function updateSendButton() {
  const hasText = messageInput.value.trim().length > 0;
  const hasCard = document.querySelector("#cardTitle").value.trim()
    && document.querySelector("#cardLocation").value.trim()
    && document.querySelector("#cardStartsAt").value;
  const ready = selectedMode === "text" ? hasText
    : selectedMode === "voice" ? Boolean(selectedFile) && !activeRecorder
      : selectedMode === "moment" ? Boolean(selectedFile)
        : Boolean(hasCard);
  sendButton.classList.toggle("is-ready", Boolean(ready));
  sendButton.setAttribute("aria-disabled", String(!ready));
}

async function createMessage() {
  if (sendingMessage) return;
  if (!selectedConversation) {
    showToast("ابدأ محادثة جديدة قبل إرسال رسالة.");
    return;
  }
  if (activeRecorder) {
    showToast("أوقف التسجيل قبل الإرسال.");
    return;
  }
  const text = messageInput.value.trim();
  if (selectedMode === "text" && !text) return;
  if (selectedMode === "voice" && !selectedFile) {
    showToast("سجّل رسالة صوتية أو أرفق تسجيلًا أولًا.");
    return;
  }
  if (selectedMode === "moment" && !selectedFile) {
    showToast("اختر صورة قبل مشاركة اللحظة.");
    return;
  }
  if (selectedMode === "card" && (
    !document.querySelector("#cardTitle").value.trim()
    || !document.querySelector("#cardLocation").value.trim()
    || !document.querySelector("#cardStartsAt").value
  )) {
    showToast("أكمل عنوان اللقاء ومكانه وموعده.");
    return;
  }

  sendingMessage = true;
  sendButton.disabled = true;
  try {
    let attachmentId;
    if (selectedFile) {
      const formData = new FormData();
      formData.set("file", selectedFile);
      const attachment = await requestApi(`/conversations/${selectedConversation.id}/attachments`, {
        method: "POST",
        formData,
      });
      attachmentId = attachment.id;
    }

    const body = {
      type: selectedMode,
      text: selectedMode === "text" ? text : "",
      caption: text,
      clientMessageId: pendingClientMessageId || (pendingClientMessageId = crypto.randomUUID()),
    };
    if (attachmentId) body.attachmentId = attachmentId;
    if (selectedMode === "card") {
      const localDate = document.querySelector("#cardStartsAt").value;
      body.card = {
        title: document.querySelector("#cardTitle").value.trim(),
        location: document.querySelector("#cardLocation").value.trim(),
        startsAt: new Date(localDate).toISOString(),
        description: text,
      };
    }
    const message = await requestApi(`/conversations/${selectedConversation.id}/messages`, { method: "POST", body });
    pendingClientMessageId = null;
    upsertMessage(message);
    messageInput.value = "";
    messageInput.style.height = "auto";
    document.querySelector("#cardTitle").value = "";
    document.querySelector("#cardLocation").value = "";
    document.querySelector("#cardStartsAt").value = "";
    setSelectedFile(null);
    selectMode("text");
    await loadConversations();
    void requestApi(`/conversations/${selectedConversation.id}/typing`, {
      method: "POST",
      body: { isTyping: false },
    }).catch(() => {});
  } catch (error) {
    pendingClientMessageId = pendingClientMessageId || crypto.randomUUID();
    throw error;
  } finally {
    sendingMessage = false;
    sendButton.disabled = false;
    updateSendButton();
  }
}

async function searchMembers(query) {
  const version = ++memberRequestVersion;
  const text = query.trim();
  if (text.length < 2) {
    userSearchResults.replaceChildren(makeElement("p", "user-search-empty", "اكتب حرفين على الأقل للبحث."));
    return;
  }
  const result = await requestApi(`/users?q=${encodeURIComponent(text)}`);
  if (version !== memberRequestVersion) return;
  renderMemberResults(result.users);
}

function renderMemberResults(users) {
  if (users.length === 0) {
    userSearchResults.replaceChildren(makeElement("p", "user-search-empty", "لم نعثر على أشخاص بهذا الاسم."));
    return;
  }
  const results = users.map((user) => {
    const label = makeElement("label", `user-search-result${selectedMembers.has(user.id) ? " is-selected" : ""}`);
    const checkbox = makeElement("input");
    checkbox.type = "checkbox";
    checkbox.value = user.id;
    checkbox.checked = selectedMembers.has(user.id);
    checkbox.setAttribute("aria-label", `اختيار ${user.displayName}`);
    const avatar = makeElement("span", `avatar ${avatarClass(user.displayName)}`, initials(user.displayName));
    avatar.setAttribute("aria-hidden", "true");
    const copy = makeElement("span", "user-result-copy");
    copy.append(makeElement("strong", "", user.displayName), makeElement("span", "", `@${user.username}`));
    label.append(checkbox, avatar, copy);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) selectedMembers.add(user.id);
      else selectedMembers.delete(user.id);
      label.classList.toggle("is-selected", checkbox.checked);
      updateNewConversationForm();
    });
    label.addEventListener("dblclick", safely(async () => {
      selectedMembers = new Set([user.id]);
      await submitNewConversation();
    }));
    return label;
  });
  userSearchResults.replaceChildren(...results);
}

function updateNewConversationForm() {
  const group = selectedMembers.size > 1;
  document.querySelector("#groupNameField").hidden = !group;
  const submit = document.querySelector("#createGroupButton");
  submit.textContent = group ? "إنشاء مجموعة" : "بدء المحادثة";
  submit.disabled = selectedMembers.size === 0 || (group && !document.querySelector("#groupName").value.trim());
  document.querySelector("#newConversationTitle").textContent = group ? "مجموعة جديدة" : "محادثة جديدة";
}

async function submitNewConversation() {
  if (selectedMembers.size === 0) return;
  const group = selectedMembers.size > 1;
  const name = document.querySelector("#groupName").value.trim();
  if (group && !name) {
    conversationError.textContent = "اكتب اسمًا للمجموعة.";
    conversationError.hidden = false;
    return;
  }
  const button = document.querySelector("#createGroupButton");
  button.disabled = true;
  try {
    const result = await requestApi("/conversations", {
      method: "POST",
      body: {
        memberIds: [...selectedMembers],
        ...(group ? { name, type: "group" } : {}),
      },
    });
    newConversationDialog.close();
    selectedMembers.clear();
    document.querySelector("#groupName").value = "";
    document.querySelector("#memberSearch").value = "";
    conversationError.hidden = true;
    await loadConversations();
    await openConversation(result.conversation);
  } finally {
    updateNewConversationForm();
  }
}

async function startRecording() {
  if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
    showToast("التسجيل الصوتي غير مدعوم في هذا المتصفح.");
    return;
  }
  try {
    activeRecordingStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mimeType = ["audio/webm;codecs=opus", "audio/ogg;codecs=opus", "audio/mp4"]
      .find((candidate) => MediaRecorder.isTypeSupported(candidate));
    activeRecorder = new MediaRecorder(activeRecordingStream, mimeType ? { mimeType } : undefined);
    recordingParts = [];
    activeRecorder.addEventListener("dataavailable", (event) => {
      if (event.data.size > 0) recordingParts.push(event.data);
    });
    activeRecorder.addEventListener("stop", () => {
      const mime = activeRecorder?.mimeType || recordingParts[0]?.type || "audio/webm";
      const extension = mime.includes("ogg") ? "ogg" : mime.includes("mp4") ? "m4a" : "webm";
      const blob = new Blob(recordingParts, { type: mime });
      if (blob.size > 0) setSelectedFile(new File([blob], `mada-voice.${extension}`, { type: mime }));
      activeRecordingStream?.getTracks().forEach((track) => track.stop());
      activeRecordingStream = null;
      activeRecorder = null;
      recordingParts = [];
      recordButton.classList.remove("is-recording");
      recordButton.setAttribute("aria-label", "بدء تسجيل رسالة صوتية");
      recordButton.title = "بدء تسجيل رسالة صوتية";
      updateSendButton();
    }, { once: true });
    activeRecorder.start();
    recordButton.classList.add("is-recording");
    recordButton.setAttribute("aria-label", "إيقاف التسجيل");
    recordButton.title = "إيقاف التسجيل";
    showToast("يجري التسجيل. اضغط الزر مجددًا عند الانتهاء.");
  } catch (error) {
    activeRecordingStream?.getTracks().forEach((track) => track.stop());
    activeRecordingStream = null;
    activeRecorder = null;
    showToast(error.name === "NotAllowedError"
      ? "اسمح بالوصول إلى الميكروفون لتسجيل رسالة صوتية."
      : "تعذّر بدء التسجيل الصوتي.");
  }
}

function stopRecording() {
  if (activeRecorder?.state === "recording") activeRecorder.stop();
}

function sendTyping(isTyping) {
  if (!selectedConversation) return;
  void requestApi(`/conversations/${selectedConversation.id}/typing`, {
    method: "POST",
    body: { isTyping },
  }).catch((error) => {
    if (error.status !== 401) console.error("تعذّر تحديث حالة الكتابة.", error);
  });
}

function bindEvents() {
  for (const button of document.querySelectorAll(".filter-button")) {
    button.addEventListener("click", () => {
      for (const filterButton of document.querySelectorAll(".filter-button")) {
        const active = filterButton === button;
        filterButton.classList.toggle("is-active", active);
        filterButton.setAttribute("aria-pressed", String(active));
      }
      renderConversationList();
    });
  }

  document.querySelector("#chatSearch").addEventListener("input", refreshConversationsAfterTyping);
  document.querySelector("#newChatButton").addEventListener("click", () => {
    if (!currentUser) {
      showAuthDialog();
      return;
    }
    selectedMembers = new Set();
    userSearchResults.replaceChildren(makeElement("p", "user-search-empty", "اكتب حرفين على الأقل للبحث."));
    conversationError.hidden = true;
    document.querySelector("#groupName").value = "";
    updateNewConversationForm();
    newConversationDialog.showModal();
  });
  document.querySelector("#backButton").addEventListener("click", () => workspace.classList.remove("is-chat-open"));
  document.querySelector("#chatSearchButton").addEventListener("click", () => {
    const panel = document.querySelector("#chatSearchPanel");
    panel.hidden = !panel.hidden;
    if (panel.hidden) {
      document.querySelector("#messageSearch").value = "";
      void fetchMessages().catch(showApiError);
    } else {
      document.querySelector("#messageSearch").focus();
    }
  });
  document.querySelector("#closeMessageSearch").addEventListener("click", () => {
    document.querySelector("#chatSearchPanel").hidden = true;
    document.querySelector("#messageSearch").value = "";
    void fetchMessages().catch(showApiError);
  });
  document.querySelector("#messageSearch").addEventListener("input", () => {
    window.clearTimeout(messageSearchTimer);
    messageSearchTimer = window.setTimeout(() => void fetchMessages(messageSearchValue()).catch(showApiError), 220);
  });

  document.querySelector("#attachmentButton").addEventListener("click", () => attachmentInput.click());
  attachmentInput.addEventListener("change", () => {
    const file = attachmentInput.files?.[0];
    attachmentInput.value = "";
    if (!file) return;
    if (!fileMatchesMode(file, selectedMode)) {
      showToast(selectedMode === "voice" ? "اختر ملفًا صوتيًا." : "اختر صورة للحظة.");
      return;
    }
    if (file.size > 12 * 1024 * 1024) {
      showToast("حجم الملف أكبر من ١٢ ميغابايت.");
      return;
    }
    setSelectedFile(file);
  });
  recordButton.addEventListener("click", () => {
    if (activeRecorder?.state === "recording") stopRecording();
    else void startRecording();
  });

  for (const button of document.querySelectorAll(".tool-button")) {
    button.addEventListener("click", () => selectMode(button.dataset.mode));
  }
  document.querySelector("#dismissMode").addEventListener("click", () => selectMode("text"));
  messageForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void createMessage().catch(showApiError);
  });
  messageInput.addEventListener("input", () => {
    messageInput.style.height = "auto";
    messageInput.style.height = `${Math.min(messageInput.scrollHeight, 96)}px`;
    updateSendButton();
    const now = Date.now();
    if (messageInput.value.trim() && now - lastTypingNotice > 900) {
      lastTypingNotice = now;
      sendTyping(true);
    }
    window.clearTimeout(typingTimer);
    typingTimer = window.setTimeout(() => sendTyping(false), 1400);
  });
  messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      messageForm.requestSubmit();
    }
  });
  document.querySelector("#emojiButton").addEventListener("click", () => {
    messageInput.value += " ☺";
    messageInput.dispatchEvent(new Event("input", { bubbles: true }));
    messageInput.focus();
  });

  document.querySelector("#cardTitle").addEventListener("input", updateSendButton);
  document.querySelector("#cardLocation").addEventListener("input", updateSendButton);
  document.querySelector("#cardStartsAt").addEventListener("input", updateSendButton);

  document.querySelector("#profileButton").addEventListener("click", (event) => {
    if (!currentUser) {
      event.preventDefault();
      profileMenu.open = false;
      showAuthDialog("login", { allowClose: true });
    }
  });
  document.querySelector("#logoutButton").addEventListener("click", safely(async () => {
    await requestApi("/auth/logout", { method: "POST", body: {} });
    closeEventStream();
    currentUser = null;
    conversations = [];
    selectedConversation = null;
    currentMessages = [];
    workspace.hidden = true;
    profileMenu.open = false;
    showAuthDialog("login");
  }));

  document.querySelector("#authModeSwitch").addEventListener("click", () => {
    setAuthMode(authForm.dataset.mode === "register" ? "login" : "register");
  });
  document.querySelector("#authClose").addEventListener("click", () => authDialog.close());
  authForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const registering = authForm.dataset.mode === "register";
      const submit = document.querySelector("#authSubmit");
      submit.disabled = true;
      authError.hidden = true;
      try {
        const user = await requestApi(registering ? "/auth/register" : "/auth/login", {
          method: "POST",
          body: {
            ...(registering ? { displayName: document.querySelector("#authDisplayName").value.trim() } : {}),
            ...(registering ? { username: document.querySelector("#authUsername").value.trim() } : {}),
            email: document.querySelector("#authEmail").value.trim(),
            password: document.querySelector("#authPassword").value,
          },
        });
        document.querySelector("#authPassword").value = "";
        await enterWorkspace(user.user);
      } catch (error) {
        if (error instanceof ApiError) {
          authError.textContent = error.message;
          authError.hidden = false;
        } else {
          showApiError(error);
        }
      } finally {
        submit.disabled = false;
      }
    })();
  });

  document.querySelector("#memberSearch").addEventListener("input", () => {
    window.clearTimeout(memberSearchTimer);
    const query = document.querySelector("#memberSearch").value;
    memberSearchTimer = window.setTimeout(() => void searchMembers(query).catch((error) => {
      conversationError.textContent = error.message;
      conversationError.hidden = false;
    }), 220);
  });
  document.querySelector("#groupName").addEventListener("input", updateNewConversationForm);
  newConversationForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitNewConversation().catch((error) => {
      conversationError.textContent = error.message;
      conversationError.hidden = false;
      document.querySelector("#createGroupButton").disabled = false;
    });
  });
  document.querySelector("#conversationClose").addEventListener("click", () => newConversationDialog.close());

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      document.querySelector("#chatSearch").focus();
    }
  });
}

async function bootstrap() {
  try {
    const health = await requestApi("/health");
    if (health.status !== "ok") throw new ApiError(503, "SERVICE_UNAVAILABLE", "الخادم غير جاهز.");
    const csrf = await requestApi("/auth/csrf");
    csrfToken = csrf.csrfToken;
    const session = await requestApi("/auth/me");
    await enterWorkspace(session.user);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      setConnectionStatus(true, "الخادم متصل");
      workspace.hidden = true;
      showAuthDialog("register");
      return;
    }
    setConnectionStatus(false, "شغّل الخادم لبدء استخدام مَدى");
    showToast(error.message || "تعذّر الاتصال بالخادم.");
  }
}

bindEvents();
updateSendButton();
void bootstrap();
