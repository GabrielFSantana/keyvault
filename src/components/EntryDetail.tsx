import { Copy, Eye, EyeOff, Pencil, Star, Trash2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { Alert } from "@/components/common";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { api, isSessionEnded, type EntryDetail as Detail, type SecretRef } from "@/lib/api";
import { errorMessage, formatDate } from "@/lib/messages";
import { REVEAL_MS } from "@/lib/policy";

const MASK = "••••••••••••";

function without(o: Record<string, string>, k: string): Record<string, string> {
  return Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));
}

function keyOf(r: SecretRef): string {
  return r.kind === "password" ? "password" : `field:${r.fieldId}`;
}

/** Revelações temporárias: no máximo 15 s; remascaradas ao perder foco, ao navegar (desmontar) e
 *  ao bloquear (a árvore inteira é desmontada). */
function useReveals(
  session: number,
  entryId: string,
  onSessionEnded: () => void,
  onToast: (m: string) => void,
) {
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const timers = useRef<Map<string, number>>(new Map());

  const hideAll = useCallback(() => {
    for (const t of timers.current.values()) window.clearTimeout(t);
    timers.current.clear();
    setRevealed({});
  }, []);

  useEffect(() => {
    const onBlur = () => {
      hideAll();
    };
    const onVis = () => {
      if (document.visibilityState !== "visible") hideAll();
    };
    window.addEventListener("blur", onBlur);
    document.addEventListener("visibilitychange", onVis);
    const pending = timers.current;
    return () => {
      // Ao desmontar (navegar/bloquear) o estado revelado deixa de existir; só cancelamos timers.
      window.removeEventListener("blur", onBlur);
      document.removeEventListener("visibilitychange", onVis);
      for (const t of pending.values()) window.clearTimeout(t);
      pending.clear();
    };
  }, [hideAll]);

  const toggle = useCallback(
    async (r: SecretRef) => {
      const k = keyOf(r);
      if (k in revealed) {
        const t = timers.current.get(k);
        if (t) window.clearTimeout(t);
        timers.current.delete(k);
        setRevealed((cur) => without(cur, k));
        return;
      }
      try {
        const res = await api.reveal(session, entryId, r);
        if (res.generation !== session) return; // resposta de sessão antiga: descartada
        if (!document.hasFocus()) return; // perdeu o foco durante a chamada
        setRevealed((cur) => ({ ...cur, [k]: res.value }));
        const ms = Math.min(res.expiresInMs, REVEAL_MS);
        timers.current.set(
          k,
          window.setTimeout(() => {
            timers.current.delete(k);
            setRevealed((cur) => without(cur, k));
          }, ms),
        );
      } catch (e) {
        if (isSessionEnded(e)) onSessionEnded();
        else onToast(errorMessage(e));
      }
    },
    [entryId, onSessionEnded, onToast, revealed, session],
  );

  return { revealed, toggle };
}

function SecretRow({
  label,
  present,
  value,
  onToggle,
  onCopy,
}: {
  label: string;
  present: boolean;
  value: string | undefined;
  onToggle: () => void;
  onCopy: () => void;
}) {
  return (
    <div className="grid gap-1">
      <dt className="text-muted-foreground text-xs font-medium">{label}</dt>
      <dd className="flex items-center gap-2">
        {/* O valor revelado nunca vai para atributos (aria-label/title). */}
        <code className="bg-muted min-h-8 flex-1 rounded px-2 py-1.5 font-mono text-sm break-all select-text">
          {present ? (value ?? MASK) : <span className="text-muted-foreground italic">vazio</span>}
        </code>
        {present ? (
          <>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onToggle}
              aria-pressed={value !== undefined}
              aria-label={`${value !== undefined ? "Ocultar" : "Revelar"} ${label}`}
            >
              {value !== undefined ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
              {value !== undefined ? "Ocultar" : "Revelar"}
            </Button>
            {/* Rótulos usam somente o NOME do campo, nunca o valor secreto. */}
            <Button type="button" variant="outline" size="sm" onClick={onCopy} aria-label={`Copiar ${label}`}>
              <Copy aria-hidden /> Copiar
            </Button>
          </>
        ) : null}
      </dd>
    </div>
  );
}

function PlainRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-muted-foreground text-xs font-medium">{label}</dt>
      <dd className="text-sm break-all whitespace-pre-wrap">
        {value || <span className="text-muted-foreground italic">vazio</span>}
      </dd>
    </div>
  );
}

export function EntryDetail({
  session,
  detail,
  onEdit,
  onDeleted,
  onSessionEnded,
  onToast,
}: {
  session: number;
  detail: Detail;
  onEdit: () => void;
  onDeleted: () => void;
  onSessionEnded: () => void;
  onToast: (m: string) => void;
}) {
  const { revealed, toggle } = useReveals(session, detail.id, onSessionEnded, onToast);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function copy(r: SecretRef, label: string) {
    try {
      const res = await api.copy(session, detail.id, r);
      if (res.generation !== session) return;
      onToast(
        `${label} copiado(a). A área de transferência será limpa em ${Math.round(res.clearsInMs / 1000)} s se ainda contiver o mesmo conteúdo.`,
      );
    } catch (e) {
      if (isSessionEnded(e)) onSessionEnded();
      else onToast(errorMessage(e));
    }
  }

  async function remove() {
    setError(null);
    try {
      await api.remove(session, detail.id);
      onDeleted();
    } catch (e) {
      if (isSessionEnded(e)) onSessionEnded();
      else setError(errorMessage(e));
    }
  }

  return (
    <article className="grid gap-4" aria-labelledby="entry-title">
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="entry-title" className="flex items-center gap-2 text-xl font-semibold break-words">
            {detail.favorite ? (
              <>
                <Star aria-hidden className="size-5 shrink-0 fill-current" />
                <span className="sr-only">Favorito: </span>
              </>
            ) : null}
            {detail.title}
          </h2>
          <p className="text-muted-foreground text-xs">
            Criado em {formatDate(detail.createdAtMs)} · Alterado em {formatDate(detail.updatedAtMs)}
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" onClick={onEdit}>
            <Pencil aria-hidden /> Editar
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setConfirmDelete(true);
            }}
          >
            <Trash2 aria-hidden /> Excluir
          </Button>
        </div>
      </header>
      {error ? <Alert kind="error">{error}</Alert> : null}
      <dl className="grid gap-3">
        <PlainRow label="Usuário" value={detail.username} />
        <SecretRow
          label="Senha"
          present={detail.hasPassword}
          value={revealed.password}
          onToggle={() => void toggle({ kind: "password" })}
          onCopy={() => void copy({ kind: "password" }, "Senha")}
        />
        {/* URL exibida somente como texto (sem link/navegação) no MVP. */}
        <PlainRow label="URL" value={detail.url} />
        <PlainRow label="Notas" value={detail.notes} />
        {detail.tags.length > 0 ? (
          <div className="grid gap-1">
            <dt className="text-muted-foreground text-xs font-medium">Tags</dt>
            <dd className="flex flex-wrap gap-1">
              {detail.tags.map((t) => (
                <Badge key={t} variant="secondary">
                  {t}
                </Badge>
              ))}
            </dd>
          </div>
        ) : null}
      </dl>
      {detail.fields.length > 0 ? <Separator /> : null}
      {/* Campos personalizados em lista própria: <dl> só pode conter grupos dt/dd. */}
      <dl className="grid gap-3" aria-label="Campos personalizados">
        {detail.fields.map((f) =>
          f.secret ? (
            <SecretRow
              key={f.id}
              label={f.name}
              present={f.hasValue}
              value={revealed[`field:${f.id}`]}
              onToggle={() => void toggle({ kind: "field", fieldId: f.id })}
              onCopy={() => void copy({ kind: "field", fieldId: f.id }, f.name)}
            />
          ) : (
            <PlainRow key={f.id} label={f.name} value={f.value ?? ""} />
          ),
        )}
      </dl>
      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Excluir esta entrada?</AlertDialogTitle>
            <AlertDialogDescription>
              Não há lixeira: a exclusão é definitiva neste cofre. Backups antigos e a retenção física do
              disco podem manter versões anteriores cifradas.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction onClick={() => void remove()}>Excluir definitivamente</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </article>
  );
}
