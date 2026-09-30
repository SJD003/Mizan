import {
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

const emptyState = () => ({
  schemaVersion: 1,
  users: {},
  conversations: {},
  messages: {},
  attachments: {},
  passwordResets: {},
});

export class JsonStore {
  #state = emptyState();
  #queue = Promise.resolve();
  #lock;
  #lockPath;
  #statePath;

  constructor(dataDirectory) {
    this.#statePath = join(dataDirectory, "mada.json");
    this.uploadDirectory = join(dataDirectory, "uploads");
    this.#lockPath = join(dataDirectory, "mada.lock");
  }

  async open() {
    await mkdir(this.uploadDirectory, { recursive: true });
    try {
      this.#lock = await open(this.#lockPath, "wx", 0o600);
      await this.#lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let active = true;
      try {
        const owner = JSON.parse(await readFile(this.#lockPath, "utf8"));
        try {
          process.kill(owner.pid, 0);
        } catch (processError) {
          if (processError.code === "ESRCH") active = false;
          else throw processError;
        }
      } catch (readError) {
        if (readError.code === "ENOENT") active = false;
        else if (!(readError instanceof SyntaxError)) throw readError;
        else active = false;
      }
      if (active) throw new Error(`Another Mada server already owns ${this.#lockPath}.`);
      await rm(this.#lockPath, { force: true });
      this.#lock = await open(this.#lockPath, "wx", 0o600);
      await this.#lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    }

    try {
      const contents = await readFile(this.#statePath, "utf8");
      this.#state = JSON.parse(contents);
      if (
        this.#state.schemaVersion !== 1
        || !this.#state.users
        || !this.#state.conversations
        || !this.#state.messages
        || !this.#state.attachments
      ) {
        throw new Error("The Mada database is incompatible or corrupted.");
      }
      if (this.#state.passwordResets === undefined) this.#state.passwordResets = {};
      if (!this.#state.passwordResets || typeof this.#state.passwordResets !== "object" || Array.isArray(this.#state.passwordResets)) {
        throw new Error("The Mada password reset data is incompatible or corrupted.");
      }
    } catch (error) {
      if (error.code !== "ENOENT") {
        await this.close();
        throw error instanceof SyntaxError
          ? new Error("The Mada database contains invalid JSON.", { cause: error })
          : error;
      }
      await this.#persist(this.#state);
    }

    const info = await stat(this.uploadDirectory);
    if (!info.isDirectory()) throw new Error("The upload path is not a directory.");
    return this;
  }

  read(selector) {
    return selector(this.#state);
  }

  transact(operation) {
    const task = this.#queue.then(async () => {
      const next = structuredClone(this.#state);
      const result = await operation(next);
      await this.#persist(next);
      this.#state = next;
      return result;
    });
    this.#queue = task.catch(() => {});
    return task;
  }

  async #persist(state) {
    const temporaryPath = `${this.#statePath}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, JSON.stringify(state), { encoding: "utf8", flag: "wx", mode: 0o600 });
      await rename(temporaryPath, this.#statePath);
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => {});
      throw error;
    }
  }

  async close() {
    await this.#queue;
    await this.#lock?.close();
    this.#lock = undefined;
    if (this.#lockPath) await rm(this.#lockPath, { force: true });
  }
}
