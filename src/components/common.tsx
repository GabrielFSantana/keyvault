import { Eye, EyeOff } from "lucide-react";
import { useId, useState, type ComponentProps, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

/** Campo de senha com alternância de visibilidade. Sem autocomplete/correção ortográfica. */
export function PasswordInput({
  label,
  value,
  onChange,
  autoFocus,
  describedBy,
  invalid,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  autoFocus?: boolean;
  describedBy?: string;
  invalid?: boolean;
}) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <Input
          id={id}
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
          }}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          autoFocus={autoFocus}
          aria-describedby={describedBy}
          aria-invalid={invalid ? true : undefined}
          className="font-mono"
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={() => {
            setVisible((v) => !v);
          }}
          aria-label={visible ? "Ocultar senha digitada" : "Mostrar senha digitada"}
          aria-pressed={visible}
        >
          {visible ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
        </Button>
      </div>
    </div>
  );
}

/** Mensagem de status/erro: ícone textual + texto (não depende só de cor). */
export function Alert({
  kind,
  children,
  className,
}: {
  kind: "error" | "info" | "success" | "warning";
  children: ReactNode;
  className?: string;
}) {
  const prefix = { error: "Erro:", info: "Informação:", success: "Concluído:", warning: "Atenção:" }[kind];
  const tone = {
    error: "border-destructive/50 bg-destructive/5 text-destructive",
    info: "border-border bg-muted text-foreground",
    success: "border-emerald-700/40 bg-emerald-50 text-emerald-900",
    warning: "border-amber-700/40 bg-amber-50 text-amber-950",
  }[kind];
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      className={cn("rounded-md border px-3 py-2 text-sm", tone, className)}
    >
      <span className="font-semibold">{prefix}</span> {children}
    </div>
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: (id: string) => ReactNode;
  hint?: string;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children(id)}
      {hint ? (
        <p id={hintId} className="text-muted-foreground text-xs">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function TextInput(props: ComponentProps<typeof Input>) {
  return <Input autoComplete="off" spellCheck={false} {...props} />;
}

/** Conta caracteres Unicode (valores escalares) e bytes UTF-8 — mesmas regras do Rust. */
export function passwordStats(p: string): { chars: number; bytes: number } {
  return { chars: Array.from(p).length, bytes: new TextEncoder().encode(p).length };
}
