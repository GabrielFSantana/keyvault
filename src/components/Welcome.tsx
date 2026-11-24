import { KeyRound } from "lucide-react";
import { useState, type SyntheticEvent } from "react";

import { Alert, PasswordInput, passwordStats } from "@/components/common";
import { RestoreDialog } from "@/components/RestoreDialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { api, type Status } from "@/lib/api";
import { errorMessage } from "@/lib/messages";
import { MAX_BYTES, MIN_CHARS } from "@/lib/policy";

export function Welcome({
  onStatus,
  onCreated,
}: {
  onStatus: (s: Status) => void;
  onCreated: (s: Status) => void;
}) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const stats = passwordStats(password);
  const lengthOk = stats.chars >= MIN_CHARS && stats.bytes <= MAX_BYTES;
  const matches = password === confirmation && password.length > 0;

  async function submit(e: SyntheticEvent) {
    e.preventDefault();
    if (!lengthOk || !matches || !understood) return;
    setBusy(true);
    setError(null);
    try {
      const s = await api.create(password, confirmation);
      setPassword("");
      setConfirmation("");
      onCreated(s);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-full max-w-xl flex-col justify-center gap-4 p-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <KeyRound aria-hidden /> Criar cofre do KeyVault
          </CardTitle>
          <CardDescription>
            Seus dados ficam somente neste computador, cifrados com uma senha mestra que só você conhece.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4" onSubmit={(e) => void submit(e)} noValidate>
            <Alert kind="warning">
              Não existe recuperação de senha. Se você perder a senha mestra, os dados do cofre e de todos os
              backups feitos com ela ficam permanentemente inacessíveis.
            </Alert>
            <PasswordInput
              label="Senha mestra"
              value={password}
              onChange={setPassword}
              autoFocus
              describedBy="pw-rules"
              invalid={password.length > 0 && !lengthOk}
            />
            <p id="pw-rules" className="text-muted-foreground text-xs">
              Mínimo de {MIN_CHARS} caracteres; máximo de {MAX_BYTES} bytes em UTF-8. Espaços e colagem são
              permitidos; não exigimos símbolos. Uma frase longa e única é uma boa escolha. Atual:{" "}
              {stats.chars} caracteres, {stats.bytes} bytes.
            </p>
            <PasswordInput
              label="Confirmar senha mestra"
              value={confirmation}
              onChange={setConfirmation}
              invalid={confirmation.length > 0 && !matches}
            />
            {confirmation.length > 0 && !matches ? (
              <Alert kind="error">A confirmação não corresponde à senha.</Alert>
            ) : null}
            <div className="flex items-start gap-2">
              <Checkbox
                id="understood"
                checked={understood}
                onCheckedChange={(v) => {
                  setUnderstood(v === true);
                }}
              />
              <Label htmlFor="understood" className="leading-snug font-normal">
                Entendo que a perda da senha mestra é irreversível e que devo guardar backups criptografados
                em mídia separada.
              </Label>
            </div>
            {error ? <Alert kind="error">{error}</Alert> : null}
            <Button type="submit" disabled={busy || !lengthOk || !matches || !understood}>
              {busy ? "Criando cofre (derivando chave)…" : "Criar cofre"}
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
        Já tenho um backup .keyvault — restaurar como novo cofre
      </Button>
      <RestoreDialog open={restoreOpen} onOpenChange={setRestoreOpen} onRestored={onStatus} />
    </main>
  );
}
