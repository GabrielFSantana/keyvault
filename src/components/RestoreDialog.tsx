import { useState } from "react";

import { Alert, PasswordInput, passwordStats } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api, type Status } from "@/lib/api";
import { errorMessage } from "@/lib/messages";
import { MAX_BYTES, MIN_CHARS } from "@/lib/policy";

type Step =
  | { kind: "intro" }
  | { kind: "password"; token: string; fileName: string; revision: number }
  | { kind: "newPassword"; token: string; entryCount: number }
  | { kind: "done"; entryCount: number };

/** Restauração em etapas: arquivo escolhido em diálogo nativo do Rust → senha do backup →
 *  autenticação e validação completas → contagem → nova senha confirmada → novo cofre. */
export function RestoreDialog({
  open,
  onOpenChange,
  onRestored,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onRestored: (s: Status) => void;
}) {
  const [step, setStep] = useState<Step>({ kind: "intro" });
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setStep({ kind: "intro" });
    setPw("");
    setPw2("");
    setError(null);
  }

  function close() {
    if (step.kind === "done") void api.status().then(onRestored, () => undefined);
    if (step.kind === "password" || step.kind === "newPassword") {
      void api.restore({ step: "cancel", token: step.token }).catch(() => undefined);
    }
    reset();
    onOpenChange(false);
  }

  async function run(f: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const stats = passwordStats(pw);
  const newOk = stats.chars >= MIN_CHARS && stats.bytes <= MAX_BYTES && pw === pw2;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) close();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Restaurar backup como novo cofre</DialogTitle>
          <DialogDescription>
            A restauração cria um cofre novo e independente. O cofre atual nunca é sobrescrito.
          </DialogDescription>
        </DialogHeader>

        {step.kind === "intro" ? (
          <div className="grid gap-3">
            <p className="text-sm">
              Escolha o arquivo .keyvault. Ele é validado antes de pedir a senha e só é aceito depois de
              autenticado por completo. Nada do conteúdo é exibido antes disso.
            </p>
            {error ? <Alert kind="error">{error}</Alert> : null}
            <DialogFooter>
              <Button variant="outline" onClick={close}>
                Cancelar
              </Button>
              <Button
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const r = await api.restore({ step: "select" });
                    if (r.step === "selected") {
                      setStep({
                        kind: "password",
                        token: r.token,
                        fileName: r.fileName,
                        revision: r.revision,
                      });
                    }
                  })
                }
              >
                Escolher arquivo…
              </Button>
            </DialogFooter>
          </div>
        ) : null}

        {step.kind === "password" ? (
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                const r = await api.restore({ step: "inspect", token: step.token, password: pw });
                setPw("");
                if (r.step === "inspected")
                  setStep({ kind: "newPassword", token: r.token, entryCount: r.entryCount });
              });
            }}
          >
            <p className="text-sm">
              Arquivo: <span className="font-mono">{step.fileName}</span> (revisão {step.revision}). Digite a
              senha usada quando este backup foi criado.
            </p>
            <PasswordInput label="Senha do backup" value={pw} onChange={setPw} autoFocus />
            {error ? <Alert kind="error">{error}</Alert> : null}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                Cancelar
              </Button>
              <Button type="submit" disabled={busy || !pw}>
                {busy ? "Verificando…" : "Verificar backup"}
              </Button>
            </DialogFooter>
          </form>
        ) : null}

        {step.kind === "newPassword" ? (
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (!newOk) return;
              void run(async () => {
                const r = await api.restore({
                  step: "commit",
                  token: step.token,
                  password: pw,
                  confirmation: pw2,
                });
                setPw("");
                setPw2("");
                if (r.step === "restored") {
                  // O status só é atualizado ao fechar a confirmação: atualizar agora remontaria a tela
                  // de desbloqueio (cofre selecionado mudou) e a confirmação se perderia.
                  setStep({ kind: "done", entryCount: r.entryCount });
                }
              });
            }}
          >
            <Alert kind="success">Backup autenticado e válido: {step.entryCount} entradas.</Alert>
            <p className="text-sm">
              Defina a senha mestra do novo cofre (mínimo de {MIN_CHARS} caracteres). Sem recuperação em caso
              de perda.
            </p>
            <PasswordInput label="Nova senha mestra" value={pw} onChange={setPw} autoFocus />
            <PasswordInput label="Confirmar nova senha mestra" value={pw2} onChange={setPw2} />
            {pw2 && pw !== pw2 ? <Alert kind="error">A confirmação não corresponde à senha.</Alert> : null}
            {error ? <Alert kind="error">{error}</Alert> : null}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                Cancelar
              </Button>
              <Button type="submit" disabled={busy || !newOk}>
                {busy ? "Criando novo cofre…" : "Criar novo cofre"}
              </Button>
            </DialogFooter>
          </form>
        ) : null}

        {step.kind === "done" ? (
          <div className="grid gap-3">
            <Alert kind="success">
              Novo cofre criado com {step.entryCount} entradas. Ele foi selecionado na tela de desbloqueio;
              use a nova senha.
            </Alert>
            <DialogFooter>
              <Button
                onClick={() => {
                  reset();
                  onOpenChange(false);
                  void api.status().then(onRestored, () => undefined);
                }}
              >
                Fechar
              </Button>
            </DialogFooter>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
