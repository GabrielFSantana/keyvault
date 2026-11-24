import { useState, type SyntheticEvent } from "react";

import { Alert, Field, PasswordInput, passwordStats } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { api, isSessionEnded, type Status } from "@/lib/api";
import { errorMessage } from "@/lib/messages";
import { MAX_BYTES, MIN_CHARS } from "@/lib/policy";

export function SettingsDialog({
  open,
  onOpenChange,
  session,
  status,
  hasUnsavedChanges,
  onStatus,
  onSessionEnded,
  onToast,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  session: number;
  status: Status;
  hasUnsavedChanges: boolean;
  onStatus: (s: Status) => void;
  onSessionEnded: () => void;
  onToast: (m: string) => void;
}) {
  const st = status.settings ?? { autoLockMinutes: 5, clipboardSeconds: 20, lockOnBlur: true };
  const [autoLock, setAutoLock] = useState(st.autoLockMinutes);
  const [clip, setClip] = useState(st.clipboardSeconds);
  const [lockOnBlur, setLockOnBlur] = useState(st.lockOnBlur);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ area: string; msg: string } | null>(null);

  async function run(area: string, f: () => Promise<void>) {
    setBusy(area);
    setError(null);
    try {
      await f();
    } catch (e) {
      if (isSessionEnded(e)) onSessionEnded();
      else setError({ area, msg: errorMessage(e) });
    } finally {
      setBusy(null);
    }
  }

  const stats = passwordStats(next);
  const newOk =
    stats.chars >= MIN_CHARS && stats.bytes <= MAX_BYTES && next === confirm && current.length > 0;

  function saveSettings(e: SyntheticEvent) {
    e.preventDefault();
    void run("settings", async () => {
      const s = await api.updateSettings(session, {
        autoLockMinutes: autoLock,
        clipboardSeconds: clip,
        lockOnBlur,
      });
      onStatus(s);
      onToast("Preferências salvas.");
    });
  }

  function changePassword(e: SyntheticEvent) {
    e.preventDefault();
    if (!newOk) return;
    void run("password", async () => {
      const s = await api.changePassword(session, current, next, confirm);
      setCurrent("");
      setNext("");
      setConfirm("");
      onStatus(s);
      onToast("Senha mestra alterada. Backups antigos continuam usando a senha antiga.");
    });
  }

  function exportBackup() {
    void run("backup", async () => {
      const r = await api.exportBackup(session);
      if (r.saved) onToast(`Backup criptografado salvo${r.fileName ? ` em ${r.fileName}` : ""}.`);
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Configurações e segurança</DialogTitle>
          <DialogDescription>
            Preferências do cofre, troca de senha mestra e backup criptografado.
          </DialogDescription>
        </DialogHeader>

        <section aria-labelledby="s-prefs" className="grid gap-3">
          <h3 id="s-prefs" className="font-semibold">
            Bloqueio e área de transferência
          </h3>
          <form className="grid gap-3" onSubmit={saveSettings}>
            <Field label="Bloquear após inatividade (minutos, 1 a 30)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={1}
                  max={30}
                  value={autoLock}
                  onChange={(e) => {
                    setAutoLock(Number(e.target.value));
                  }}
                />
              )}
            </Field>
            <Field label="Limpar área de transferência após (segundos, 5 a 60)">
              {(id) => (
                <Input
                  id={id}
                  type="number"
                  min={5}
                  max={60}
                  value={clip}
                  onChange={(e) => {
                    setClip(Number(e.target.value));
                  }}
                />
              )}
            </Field>
            <div className="flex items-center gap-2">
              <Switch id="blur" checked={lockOnBlur} onCheckedChange={setLockOnBlur} />
              <Label htmlFor="blur">Bloquear após 30 segundos fora de foco</Label>
            </div>
            <p className="text-muted-foreground text-xs">
              O histórico e a sincronização da área de transferência do Windows podem reter cópias; o KeyVault
              pede exclusão do histórico, mas não pode garantir. Capturas de tela e outros programas também
              podem ler o conteúdo.
            </p>
            {error?.area === "settings" ? <Alert kind="error">{error.msg}</Alert> : null}
            <Button type="submit" className="justify-self-start" disabled={busy !== null}>
              {busy === "settings" ? "Salvando…" : "Salvar preferências"}
            </Button>
          </form>
        </section>

        <Separator />

        <section aria-labelledby="s-backup" className="grid gap-3">
          <h3 id="s-backup" className="font-semibold">
            Backup criptografado (.keyvault)
          </h3>
          <p className="text-sm">
            O backup é um envelope cifrado novo, protegido pela senha mestra atual. Guarde cópias em mídia
            separada e teste a restauração. Não existe backup em texto claro.
          </p>
          {hasUnsavedChanges ? (
            <Alert kind="warning">
              Há alterações não salvas no editor. Salve ou descarte-as antes do backup.
            </Alert>
          ) : null}
          {error?.area === "backup" ? <Alert kind="error">{error.msg}</Alert> : null}
          <Button
            className="justify-self-start"
            onClick={exportBackup}
            disabled={busy !== null || hasUnsavedChanges}
          >
            {busy === "backup" ? "Gerando backup…" : "Salvar backup…"}
          </Button>
        </section>

        <Separator />

        <section aria-labelledby="s-pass" className="grid gap-3">
          <h3 id="s-pass" className="font-semibold">
            Alterar senha mestra
          </h3>
          <Alert kind="warning">
            Backups e cópias antigas continuam abrindo com a senha antiga; a troca não as revoga.
          </Alert>
          <form className="grid gap-3" onSubmit={changePassword}>
            <PasswordInput label="Senha atual" value={current} onChange={setCurrent} />
            <PasswordInput label="Nova senha mestra" value={next} onChange={setNext} />
            <PasswordInput label="Confirmar nova senha mestra" value={confirm} onChange={setConfirm} />
            <p className="text-muted-foreground text-xs">
              Mínimo de {MIN_CHARS} caracteres; máximo de {MAX_BYTES} bytes. Atual: {stats.chars} caracteres.
            </p>
            {confirm && next !== confirm ? <Alert kind="error">A confirmação não corresponde.</Alert> : null}
            {error?.area === "password" ? <Alert kind="error">{error.msg}</Alert> : null}
            <Button type="submit" className="justify-self-start" disabled={busy !== null || !newOk}>
              {busy === "password" ? "Alterando…" : "Alterar senha mestra"}
            </Button>
          </form>
        </section>

        <Separator />
        <section aria-labelledby="s-info" className="text-muted-foreground grid gap-1 text-xs">
          <h3 id="s-info" className="text-foreground font-semibold">
            Informações técnicas
          </h3>
          <p>
            Revisão do cofre: {status.revision ?? "—"} · Entradas: {status.entryCount ?? "—"}
          </p>
          {status.kdf ? (
            <p>
              Argon2id: memória {Math.round(status.kdf.mCostKib / 1024)} MiB, {status.kdf.tCost} iterações,{" "}
              {status.kdf.pCost} vias
              {status.kdf.measuredMs !== null ? ` (≈${status.kdf.measuredMs} ms neste computador)` : ""}.
            </p>
          ) : null}
          <p>
            Integração com bloqueio/suspensão do sistema: {status.osIntegration ? "ativa" : "indisponível"}.
          </p>
        </section>
      </DialogContent>
    </Dialog>
  );
}
