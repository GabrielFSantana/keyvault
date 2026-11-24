import { Lock, Plus, Search, Settings, Star } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { Alert } from "@/components/common";
import { EntryDetail } from "@/components/EntryDetail";
import { EntryEditor } from "@/components/EntryEditor";
import { SettingsDialog } from "@/components/SettingsDialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { api, isSessionEnded, type EntryDetail as Detail, type EntrySummary, type Status } from "@/lib/api";
import { errorMessage } from "@/lib/messages";
import { ACTIVITY_THROTTLE_MS } from "@/lib/policy";
import { cn } from "@/lib/utils";

type Mode = { kind: "empty" } | { kind: "view"; detail: Detail } | { kind: "edit"; detail: Detail | null };

/** Sinaliza atividade real (teclado/ponteiro) ao Rust, com rate limit. */
function useActivity(session: number) {
  useEffect(() => {
    let last = 0;
    const onInput = (e: Event) => {
      if (!e.isTrusted) return;
      const now = Date.now();
      if (now - last < ACTIVITY_THROTTLE_MS) return;
      last = now;
      void api.activity(session).catch(() => undefined);
    };
    const opts = { capture: true, passive: true } as const;
    window.addEventListener("keydown", onInput, opts);
    window.addEventListener("pointerdown", onInput, opts);
    window.addEventListener("wheel", onInput, opts);
    return () => {
      window.removeEventListener("keydown", onInput, opts);
      window.removeEventListener("pointerdown", onInput, opts);
      window.removeEventListener("wheel", onInput, opts);
    };
  }, [session]);
}

export function VaultView({
  status,
  onStatus,
  onLock,
  onSessionEnded,
  offerBackup = false,
  onBackupOffered,
}: {
  status: Status;
  onStatus: (s: Status) => void;
  onLock: () => void;
  onSessionEnded: () => void;
  offerBackup?: boolean;
  onBackupOffered?: () => void;
}) {
  const session = status.generation;
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [query, setQuery] = useState("");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [mode, setMode] = useState<Mode>({ kind: "empty" });
  const [dirty, setDirty] = useState(false);
  const [pendingNav, setPendingNav] = useState<(() => void) | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const requestSeq = useRef(0);

  useActivity(session);

  const handleError = useCallback(
    (e: unknown) => {
      if (isSessionEnded(e)) onSessionEnded();
      else setError(errorMessage(e));
    },
    [onSessionEnded],
  );

  const reload = useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const r = query.trim()
        ? await api.search(session, query, favoritesOnly)
        : await api.list(session, favoritesOnly);
      // Descarta respostas antigas (sessão diferente ou pesquisa superada).
      if (r.generation !== session || seq !== requestSeq.current) return;
      setEntries(r.entries);
    } catch (e) {
      handleError(e);
    }
  }, [favoritesOnly, handleError, query, session]);

  useEffect(() => {
    const t = window.setTimeout(() => void reload(), 120);
    return () => {
      window.clearTimeout(t);
    };
  }, [reload]);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => {
      setToast(null);
    }, 6000);
    return () => {
      window.clearTimeout(t);
    };
  }, [toast]);

  // Atalhos: Ctrl+F pesquisa, Ctrl+N nova entrada, Ctrl+L bloquear.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey) return;
      const k = e.key.toLowerCase();
      if (k === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (k === "l") {
        e.preventDefault();
        onLock();
      } else if (k === "n") {
        e.preventDefault();
        guard(() => {
          setMode({ kind: "edit", detail: null });
        });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  });

  function guard(action: () => void) {
    if (dirty) setPendingNav(() => action);
    else action();
  }

  async function open(id: string) {
    setError(null);
    try {
      const d = await api.get(session, id);
      if (d.generation !== session) return;
      setMode({ kind: "view", detail: d });
    } catch (e) {
      handleError(e);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-2 border-b px-4 py-2">
        <h1 className="mr-auto text-lg font-semibold">KeyVault</h1>
        <span className="text-muted-foreground text-xs" aria-live="polite">
          {dirty ? "Alterações não salvas" : ""}
        </span>
        <Button
          variant="outline"
          onClick={() => {
            guard(() => {
              setMode({ kind: "edit", detail: null });
            });
          }}
        >
          <Plus aria-hidden /> Nova entrada
        </Button>
        <Button
          variant="outline"
          onClick={() => {
            setSettingsOpen(true);
          }}
        >
          <Settings aria-hidden /> Configurações
        </Button>
        <Button onClick={onLock}>
          <Lock aria-hidden /> Bloquear
        </Button>
      </header>
      <div className="flex min-h-0 flex-1">
        <nav aria-label="Entradas" className="flex w-80 shrink-0 flex-col border-r">
          <div className="grid gap-2 border-b p-3">
            <div className="relative">
              <Search aria-hidden className="text-muted-foreground absolute top-2.5 left-2 size-4" />
              <Input
                ref={searchRef}
                type="search"
                aria-label="Pesquisar em título, URL, usuário, tags e notas"
                placeholder="Pesquisar (Ctrl+F)"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                }}
                className="pl-8"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch id="favs" checked={favoritesOnly} onCheckedChange={setFavoritesOnly} />
              <Label htmlFor="favs" className="font-normal">
                Somente favoritos
              </Label>
            </div>
          </div>
          <ul className="min-h-0 flex-1 overflow-y-auto p-2" aria-label={`${entries.length} entradas`}>
            {entries.length === 0 ? (
              <li className="text-muted-foreground p-3 text-sm">
                {query || favoritesOnly ? "Nenhuma entrada encontrada." : "Nenhuma entrada ainda."}
              </li>
            ) : null}
            {entries.map((e) => {
              const selected = mode.kind !== "empty" && mode.detail?.id === e.id;
              return (
                <li key={e.id}>
                  <button
                    type="button"
                    aria-current={selected ? "true" : undefined}
                    onClick={() => {
                      guard(() => void open(e.id));
                    }}
                    className={cn(
                      "hover:bg-accent focus-visible:bg-accent w-full rounded-md px-3 py-2 text-left",
                      selected && "bg-accent",
                    )}
                  >
                    <span className="flex items-center gap-1 text-sm font-medium break-words">
                      {e.favorite ? (
                        <>
                          <Star aria-hidden className="size-3.5 shrink-0 fill-current" />
                          <span className="sr-only">Favorito: </span>
                        </>
                      ) : null}
                      {e.title}
                    </span>
                    <span className="text-muted-foreground block truncate text-xs">{e.username || "—"}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto p-6">
          {error ? (
            <Alert kind="error" className="mb-4">
              {error}
            </Alert>
          ) : null}
          {mode.kind === "empty" ? (
            <p className="text-muted-foreground">Selecione uma entrada ou crie uma nova.</p>
          ) : null}
          {mode.kind === "view" ? (
            <EntryDetail
              key={mode.detail.id}
              session={session}
              detail={mode.detail}
              onEdit={() => {
                setMode({ kind: "edit", detail: mode.detail });
              }}
              onDeleted={() => {
                setMode({ kind: "empty" });
                setToast("Entrada excluída.");
                void reload();
              }}
              onSessionEnded={onSessionEnded}
              onToast={setToast}
            />
          ) : null}
          {mode.kind === "edit" ? (
            <EntryEditor
              key={mode.detail?.id ?? "new"}
              session={session}
              initial={mode.detail}
              onDirtyChange={setDirty}
              onSessionEnded={onSessionEnded}
              onCancel={() => {
                guard(() => {
                  setDirty(false);
                  setMode(mode.detail ? { kind: "view", detail: mode.detail } : { kind: "empty" });
                });
              }}
              onSaved={(id) => {
                setToast("Entrada salva.");
                void reload();
                void open(id);
              }}
            />
          ) : null}
        </main>
      </div>
      <div aria-live="polite" role="status" className="pointer-events-none fixed right-4 bottom-4 max-w-md">
        {toast ? (
          <div className="bg-primary text-primary-foreground pointer-events-auto rounded-md px-4 py-3 text-sm shadow-lg">
            {toast}
          </div>
        ) : null}
      </div>
      <SettingsDialog
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        session={session}
        status={status}
        hasUnsavedChanges={dirty}
        onStatus={onStatus}
        onSessionEnded={onSessionEnded}
        onToast={setToast}
      />
      <AlertDialog
        open={offerBackup}
        onOpenChange={(o) => {
          if (!o) onBackupOffered?.();
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cofre criado. Fazer um backup criptografado agora?</AlertDialogTitle>
            <AlertDialogDescription>
              O backup .keyvault é cifrado com a sua senha mestra e permite restaurar o cofre em caso de perda
              do computador ou do arquivo. Guarde-o em mídia separada. Sem a senha mestra, nem o backup pode
              ser aberto.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Depois</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                onBackupOffered?.();
                void api
                  .exportBackup(session)
                  .then((r) => {
                    if (r.saved)
                      setToast(`Backup criptografado salvo${r.fileName ? ` em ${r.fileName}` : ""}.`);
                  })
                  .catch(handleError);
              }}
            >
              Salvar backup…
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog
        open={pendingNav !== null}
        onOpenChange={(o) => {
          if (!o) setPendingNav(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Descartar alterações não salvas?</AlertDialogTitle>
            <AlertDialogDescription>As alterações no editor serão perdidas.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Continuar editando</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                const nav = pendingNav;
                setPendingNav(null);
                setDirty(false);
                nav?.();
              }}
            >
              Descartar
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
