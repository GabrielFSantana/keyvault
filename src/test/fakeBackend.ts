// Backend IPC falso, SOMENTE para testes de componentes/estado da UI (dados fictícios).
// Não substitui os testes nativos do Rust/Tauri.
import { vi } from "vitest";

import type { EntryDetail, LockReason, Status } from "@/lib/api";

type Handler = (args: Record<string, unknown>) => unknown;

export interface Fake {
  status: Status;
  handlers: Record<string, Handler>;
  calls: { cmd: string; args: Record<string, unknown> }[];
  emitLocked: (reason: LockReason) => void;
}

const lockedListeners: ((e: { payload: { reason: LockReason; generation: number } }) => void)[] = [];

export const fake: Fake = {
  status: baseStatus("locked"),
  handlers: {},
  calls: [],
  emitLocked: (reason) => {
    fake.status = {
      ...fake.status,
      phase: "locked",
      generation: fake.status.generation + 1,
      lastLockReason: reason,
      settings: null,
    };
    for (const l of lockedListeners) l({ payload: { reason, generation: fake.status.generation } });
  },
};

export function baseStatus(phase: Status["phase"]): Status {
  return {
    phase,
    generation: 5,
    vaults:
      phase === "uninitialized"
        ? []
        : [{ id: "0123456789abcdef0123456789abcdef", modifiedMs: 1_700_000_000_000 }],
    selectedVaultId: phase === "uninitialized" ? null : "0123456789abcdef0123456789abcdef",
    settings: phase === "unlocked" ? { autoLockMinutes: 5, clipboardSeconds: 20, lockOnBlur: true } : null,
    entryCount: phase === "unlocked" ? 1 : null,
    revision: phase === "unlocked" ? 3 : null,
    kdf: null,
    retryAfterMs: null,
    lastLockReason: null,
    osIntegration: true,
  };
}

export const XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>';

export function sampleDetail(generation: number): EntryDetail {
  return {
    generation,
    id: "aa".repeat(16),
    title: XSS,
    url: "javascript:window.__xss=3",
    username: "usuario.ficticio",
    notes: XSS,
    tags: ["infra"],
    favorite: true,
    createdAtMs: 1_700_000_000_000,
    updatedAtMs: 1_700_000_000_000,
    hasPassword: true,
    fields: [{ id: "bb".repeat(16), name: "Token", secret: true, value: null, hasValue: true }],
  };
}

export function resetFake(phase: Status["phase"]) {
  fake.status = baseStatus(phase);
  fake.calls = [];
  fake.handlers = {
    vault_status: () => fake.status,
    vault_lock: () => {
      fake.status = {
        ...baseStatus("locked"),
        generation: fake.status.generation + 1,
        lastLockReason: "manual",
      };
      return fake.status;
    },
    session_activity: () => true,
    entries_list: (a) => ({
      generation: a.session,
      entries: [
        { id: "aa".repeat(16), title: XSS, username: "usuario.ficticio", favorite: true, updatedAtMs: 1 },
      ],
    }),
    entries_search: (a) => ({ generation: a.session, entries: [] }),
    entry_get: (a) => sampleDetail(a.session as number),
    entry_reveal_secret: (a) => ({
      generation: a.session,
      value: "segredo-revelado-ficticio",
      expiresInMs: 15000,
    }),
    entry_copy_secret: (a) => ({ generation: a.session, clearsInMs: 20000 }),
  };
}

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn((cmd: string, args: Record<string, unknown> = {}) => {
    fake.calls.push({ cmd, args });
    const h = fake.handlers[cmd];
    if (!h) return Promise.reject({ code: "not_mocked" });
    try {
      return Promise.resolve(h(args));
    } catch (e) {
      return Promise.reject(e);
    }
  }),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((_name: string, cb: (e: { payload: { reason: LockReason; generation: number } }) => void) => {
    lockedListeners.push(cb);
    return Promise.resolve(() => {
      const i = lockedListeners.indexOf(cb);
      if (i >= 0) lockedListeners.splice(i, 1);
    });
  }),
}));
