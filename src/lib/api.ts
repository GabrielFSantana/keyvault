// Camada única de IPC. O frontend só chama comandos de domínio do Rust; nunca recebe chaves,
// nunca acessa banco/arquivos e não usa armazenamento persistente do navegador.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Phase = "uninitialized" | "locked" | "unlocking" | "unlocked" | "locking" | "error";
export type LockReason =
  | "manual"
  | "inactivity"
  | "focusLost"
  | "osLock"
  | "suspend"
  | "userSwitch"
  | "shutdown"
  | "appClose"
  | "restore";

export interface Settings {
  autoLockMinutes: number;
  clipboardSeconds: number;
  lockOnBlur: boolean;
}

export interface Status {
  phase: Phase;
  generation: number;
  vaults: { id: string; modifiedMs: number | null }[];
  selectedVaultId: string | null;
  settings: Settings | null;
  entryCount: number | null;
  revision: number | null;
  kdf: { mCostKib: number; tCost: number; pCost: number; measuredMs: number | null } | null;
  retryAfterMs: number | null;
  lastLockReason: LockReason | null;
  osIntegration: boolean;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  favorite: boolean;
  updatedAtMs: number;
}

export interface FieldView {
  id: string;
  name: string;
  secret: boolean;
  value: string | null;
  hasValue: boolean;
}

export interface EntryDetail {
  generation: number;
  id: string;
  title: string;
  url: string;
  username: string;
  notes: string;
  tags: string[];
  favorite: boolean;
  createdAtMs: number;
  updatedAtMs: number;
  hasPassword: boolean;
  fields: FieldView[];
}

export type SecretUpdate = { kind: "keep" } | { kind: "set"; value: string } | { kind: "clear" };

export interface FieldInput {
  id: string | null;
  name: string;
  secret: boolean;
  value: SecretUpdate;
}

export interface EntryInput {
  id: string | null;
  title: string;
  url: string;
  username: string;
  password: SecretUpdate;
  notes: string;
  tags: string[];
  favorite: boolean;
  fields: FieldInput[];
}

export type SecretRef = { kind: "password" } | { kind: "field"; fieldId: string };

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface IpcError {
  code: string;
  field?: string;
  retryAfterMs?: number;
}

export type RestoreResponse =
  | { step: "cancelled" }
  | { step: "selected"; token: string; fileName: string; revision: number }
  | { step: "inspected"; token: string; entryCount: number; revision: number }
  | { step: "restored"; vaultId: string; entryCount: number };

export function isIpcError(e: unknown): e is IpcError {
  return typeof e === "object" && e !== null && typeof (e as { code?: unknown }).code === "string";
}

/** Erros que significam "sessão encerrada": a UI deve limpar tudo e voltar ao bloqueio. */
export function isSessionEnded(e: unknown): boolean {
  return isIpcError(e) && (e.code === "locked" || e.code === "stale_session");
}

export const api = {
  status: () => invoke<Status>("vault_status"),
  create: (password: string, confirmation: string) =>
    invoke<Status>("vault_create", { password, confirmation }),
  unlock: (vaultId: string, password: string) => invoke<Status>("vault_unlock", { vaultId, password }),
  lock: () => invoke<Status>("vault_lock"),
  activity: (session: number) => invoke<boolean>("session_activity", { session }),
  list: (session: number, favoritesOnly: boolean) =>
    invoke<{ generation: number; entries: EntrySummary[] }>("entries_list", { session, favoritesOnly }),
  search: (session: number, query: string, favoritesOnly: boolean) =>
    invoke<{ generation: number; entries: EntrySummary[] }>("entries_search", {
      session,
      query,
      favoritesOnly,
    }),
  get: (session: number, id: string) => invoke<EntryDetail>("entry_get", { session, id }),
  save: (session: number, entry: EntryInput) =>
    invoke<{ generation: number; id: string; revision: number }>("entry_save", { session, entry }),
  remove: (session: number, id: string) => invoke<number>("entry_delete", { session, id }),
  generate: (session: number, options: GeneratorOptions) =>
    invoke<{ generation: number; password: string }>("password_generate", { session, options }),
  reveal: (session: number, id: string, secret: SecretRef) =>
    invoke<{ generation: number; value: string; expiresInMs: number }>("entry_reveal_secret", {
      session,
      id,
      secret,
    }),
  copy: (session: number, id: string, secret: SecretRef) =>
    invoke<{ generation: number; clearsInMs: number }>("entry_copy_secret", { session, id, secret }),
  changePassword: (session: number, current: string, newPassword: string, confirmation: string) =>
    invoke<Status>("vault_change_password", { session, current, newPassword, confirmation }),
  updateSettings: (session: number, settings: Settings) =>
    invoke<Status>("vault_settings_update", { session, settings }),
  exportBackup: (session: number) =>
    invoke<{ saved: boolean; fileName: string | null }>("backup_export", { session }),
  restore: (
    request:
      | { step: "select" }
      | { step: "inspect"; token: string; password: string }
      | { step: "commit"; token: string; password: string; confirmation: string }
      | { step: "cancel"; token: string },
  ) => invoke<RestoreResponse>("backup_restore", { request }),
  onLocked: (handler: (p: { reason: LockReason; generation: number }) => void): Promise<UnlistenFn> =>
    listen<{ reason: LockReason; generation: number }>("kv://session-locked", (e) => {
      handler(e.payload);
    }),
};
