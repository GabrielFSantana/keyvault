import { Lock } from "lucide-react";
import { useEffect, useState, type SyntheticEvent } from "react";

import { Alert, PasswordInput } from "@/components/common";
import { RestoreDialog } from "@/components/RestoreDialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { api, isIpcError, type Status } from "@/lib/api";
import { errorMessage, formatDate, shortId } from "@/lib/messages";

export function UnlockScreen({
  status,
  notice,
  onStatus,
}: {
  status: Status;
  notice: string | null;
  onStatus: (s: Status) => void;
}) {
  const [vaultId, setVaultId] = useState(status.selectedVaultId ?? status.vaults[0]?.id ?? "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryUntil, setRetryUntil] = useState<number>(() =>
    status.retryAfterMs ? Date.now() + status.retryAfterMs : 0,
  );
  const [now, setNow] = useState(() => Date.now());
  const [restoreOpen, setRestoreOpen] = useState(false);

  useEffect(() => {
    if (retryUntil <= Date.now()) return;
    const t = window.setInterval(() => {
      setNow(Date.now());
    }, 250);
    return () => {
      window.clearInterval(t);
    };
  }, [retryUntil]);

  const waiting = retryUntil > now;

  async function submit(e: SyntheticEvent) {
    e.preventDefault();
    if (!vaultId || !password || busy || waiting) return;
    setBusy(true);
    setError(null);
    try {
      const s = await api.unlock(vaultId, password);
      setPassword("");
      onStatus(s);
    } catch (err) {
      setPassword("");
      setError(errorMessage(err));
      if (isIpcError(err) && err.retryAfterMs) {
        setRetryUntil(Date.now() + err.retryAfterMs);
        setNow(Date.now());
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-full max-w-md flex-col justify-center gap-4 p-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <Lock aria-hidden /> KeyVault bloqueado
          </CardTitle>
          <CardDescription>Digite a senha mestra para desbloquear.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4" onSubmit={(e) => void submit(e)} noValidate>
            {notice ? <Alert kind="info">{notice}</Alert> : null}
            {status.vaults.length > 1 ? (
              <fieldset className="grid gap-2">
                <legend className="mb-1 text-sm font-medium">Cofre</legend>
                {status.vaults.map((v) => (
                  <div key={v.id} className="flex items-center gap-2">
                    <input
                      type="radio"
                      id={`vault-${v.id}`}
                      name="vault"
                      value={v.id}
                      checked={vaultId === v.id}
                      onChange={() => {
                        setVaultId(v.id);
                      }}
                      className="size-4 accent-current"
                    />
                    <Label htmlFor={`vault-${v.id}`} className="font-normal">
                      Cofre {shortId(v.id)}
                      {v.modifiedMs ? ` — alterado em ${formatDate(v.modifiedMs)}` : ""}
                    </Label>
                  </div>
                ))}
              </fieldset>
            ) : null}
            <PasswordInput label="Senha mestra" value={password} onChange={setPassword} autoFocus />
            {error ? <Alert kind="error">{error}</Alert> : null}
            {waiting ? (
              <p className="text-muted-foreground text-sm" aria-live="polite">
                Nova tentativa disponível em {Math.ceil((retryUntil - now) / 1000)} s.
              </p>
            ) : null}
            <Button type="submit" disabled={busy || waiting || !password || !vaultId}>
              {busy ? "Desbloqueando (derivando chave)…" : "Desbloquear"}
            </Button>
          </form>
        </CardContent>
      </Card>
      <Button
        variant="link"
        onClick={() => {
          setRestoreOpen(true);
        }}
      >
        Restaurar backup .keyvault como novo cofre
      </Button>
      <p className="text-muted-foreground text-center text-xs">
        Esqueceu a senha? Não há recuperação. Use um backup cuja senha você lembre.
      </p>
      <RestoreDialog
        open={restoreOpen}
        onOpenChange={setRestoreOpen}
        onRestored={(s) => {
          onStatus(s);
        }}
      />
    </main>
  );
}
