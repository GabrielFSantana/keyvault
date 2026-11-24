import { Plus, Trash2, Wand2 } from "lucide-react";
import { useId, useState, type SyntheticEvent } from "react";

import { Alert, Field, TextInput } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  isSessionEnded,
  type EntryDetail,
  type EntryInput,
  type GeneratorOptions,
  type SecretUpdate,
} from "@/lib/api";
import { errorMessage } from "@/lib/messages";

interface FieldDraft {
  key: string;
  id: string | null;
  name: string;
  secret: boolean;
  /** Para campos não secretos: valor visível. Para secretos: atualização pendente. */
  plain: string;
  secretUpdate: SecretUpdate;
  hadValue: boolean;
}

let draftCounter = 0;

function draftsFrom(d: EntryDetail | null): FieldDraft[] {
  return (d?.fields ?? []).map((f): FieldDraft => ({
    key: `f${++draftCounter}`,
    id: f.id,
    name: f.name,
    secret: f.secret,
    plain: f.value ?? "",
    secretUpdate: { kind: "keep" },
    hadValue: f.hasValue,
  }));
}

export const DEFAULT_GENERATOR: GeneratorOptions = {
  length: 24,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

function SecretEditor({
  label,
  hadValue,
  update,
  onChange,
  onGenerate,
}: {
  label: string;
  hadValue: boolean;
  update: SecretUpdate;
  onChange: (u: SecretUpdate) => void;
  onGenerate?: () => void;
}) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  if (update.kind !== "set") {
    return (
      <div className="grid gap-1.5">
        <span className="text-sm font-medium" id={id}>
          {label}
        </span>
        <div className="flex flex-wrap items-center gap-2" aria-labelledby={id} role="group">
          <span className="text-muted-foreground text-sm">
            {update.kind === "clear"
              ? "Será removida ao salvar."
              : hadValue
                ? "Inalterada (oculta)."
                : "Vazia."}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              onChange({ kind: "set", value: "" });
            }}
          >
            {hadValue ? "Substituir" : "Definir"}
          </Button>
          {onGenerate ? (
            <Button type="button" variant="outline" size="sm" onClick={onGenerate}>
              <Wand2 aria-hidden /> Gerar
            </Button>
          ) : null}
          {hadValue && update.kind === "keep" ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                onChange({ kind: "clear" });
              }}
            >
              Remover
            </Button>
          ) : null}
          {update.kind === "clear" ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                onChange({ kind: "keep" });
              }}
            >
              Desfazer
            </Button>
          ) : null}
        </div>
      </div>
    );
  }
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <Input
          id={id}
          type={visible ? "text" : "password"}
          value={update.value}
          onChange={(e) => {
            onChange({ kind: "set", value: e.target.value });
          }}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
        />
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            setVisible((v) => !v);
          }}
          aria-pressed={visible}
        >
          {visible ? "Ocultar" : "Mostrar"}
        </Button>
        {onGenerate ? (
          <Button type="button" variant="outline" size="sm" onClick={onGenerate}>
            <Wand2 aria-hidden /> Gerar
          </Button>
        ) : null}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => {
            onChange({ kind: "keep" });
          }}
        >
          Cancelar
        </Button>
      </div>
    </div>
  );
}

export function EntryEditor({
  session,
  initial,
  onSaved,
  onCancel,
  onDirtyChange,
  onSessionEnded,
}: {
  session: number;
  initial: EntryDetail | null;
  onSaved: (id: string) => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onSessionEnded: () => void;
}) {
  const [title, setTitle] = useState(initial?.title ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [tags, setTags] = useState((initial?.tags ?? []).join(", "));
  const [favorite, setFavorite] = useState(initial?.favorite ?? false);
  const [password, setPassword] = useState<SecretUpdate>({ kind: "keep" });
  const [fields, setFields] = useState<FieldDraft[]>(() => draftsFrom(initial));
  const [gen, setGen] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [showGen, setShowGen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function dirty<T>(set: (v: T) => void) {
    return (v: T) => {
      set(v);
      onDirtyChange(true);
    };
  }

  /** `target`: "password" ou a chave de um campo personalizado. */
  async function generate(target: string) {
    setError(null);
    try {
      const r = await api.generate(session, gen);
      if (r.generation !== session) return;
      if (target === "password") dirty(setPassword)({ kind: "set", value: r.password });
      else
        dirty(setFields)(
          fields.map((f) =>
            f.key === target ? { ...f, secretUpdate: { kind: "set", value: r.password } } : f,
          ),
        );
    } catch (e) {
      if (isSessionEnded(e)) onSessionEnded();
      else setError(errorMessage(e));
    }
  }

  async function submit(e: SyntheticEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setError("O título é obrigatório.");
      return;
    }
    const input: EntryInput = {
      id: initial?.id ?? null,
      title,
      url,
      username,
      password,
      notes,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0),
      favorite,
      fields: fields.map((f) => ({
        id: f.id,
        name: f.name,
        secret: f.secret,
        value: f.secret
          ? f.id === null && f.secretUpdate.kind === "keep"
            ? { kind: "set", value: "" }
            : f.secretUpdate
          : { kind: "set", value: f.plain },
      })),
    };
    setBusy(true);
    setError(null);
    try {
      const r = await api.save(session, input);
      if (r.generation !== session) return;
      onDirtyChange(false);
      onSaved(r.id);
    } catch (err) {
      if (isSessionEnded(err)) onSessionEnded();
      else setError(`${errorMessage(err)} As alterações continuam não salvas.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="grid gap-4" onSubmit={(e) => void submit(e)} noValidate aria-labelledby="editor-title">
      <h2 id="editor-title" className="text-xl font-semibold">
        {initial ? "Editar entrada" : "Nova entrada"}
      </h2>
      <Field label="Título (obrigatório)">
        {(id) => (
          <TextInput
            id={id}
            value={title}
            onChange={(e) => {
              dirty(setTitle)(e.target.value);
            }}
            autoFocus
            aria-required
          />
        )}
      </Field>
      <Field label="Usuário">
        {(id) => (
          <TextInput
            id={id}
            value={username}
            onChange={(e) => {
              dirty(setUsername)(e.target.value);
            }}
          />
        )}
      </Field>
      <SecretEditor
        label="Senha"
        hadValue={initial?.hasPassword ?? false}
        update={password}
        onChange={dirty(setPassword)}
        onGenerate={() => void generate("password")}
      />
      {showGen ? (
        <fieldset className="grid gap-2 rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">Gerador de senhas</legend>
          <Field label="Comprimento (16 a 128)">
            {(id) => (
              <Input
                id={id}
                type="number"
                min={16}
                max={128}
                value={gen.length}
                onChange={(e) => {
                  setGen({ ...gen, length: Number(e.target.value) });
                }}
              />
            )}
          </Field>
          {(
            [
              ["lowercase", "Minúsculas (a–z)"],
              ["uppercase", "Maiúsculas (A–Z)"],
              ["digits", "Dígitos (0–9)"],
              ["symbols", "Símbolos"],
              ["excludeAmbiguous", "Excluir ambíguos (I, l, 1, O, 0, o)"],
            ] as const
          ).map(([k, label]) => (
            <div key={k} className="flex items-center gap-2">
              <Checkbox
                id={`gen-${k}`}
                checked={gen[k]}
                onCheckedChange={(v) => {
                  setGen({ ...gen, [k]: v === true });
                }}
              />
              <Label htmlFor={`gen-${k}`} className="font-normal">
                {label}
              </Label>
            </div>
          ))}
        </fieldset>
      ) : null}
      <Button
        type="button"
        variant="link"
        className="justify-self-start px-0"
        onClick={() => {
          setShowGen((v) => !v);
        }}
        aria-expanded={showGen}
      >
        {showGen ? "Ocultar opções do gerador" : "Opções do gerador"}
      </Button>
      <Field label="URL (exibida somente como texto)">
        {(id) => (
          <TextInput
            id={id}
            value={url}
            onChange={(e) => {
              dirty(setUrl)(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label="Notas">
        {(id) => (
          <Textarea
            id={id}
            value={notes}
            rows={4}
            onChange={(e) => {
              dirty(setNotes)(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label="Tags" hint="Separe por vírgulas.">
        {(id) => (
          <TextInput
            id={id}
            value={tags}
            onChange={(e) => {
              dirty(setTags)(e.target.value);
            }}
          />
        )}
      </Field>
      <div className="flex items-center gap-2">
        <Switch id="fav" checked={favorite} onCheckedChange={dirty(setFavorite)} />
        <Label htmlFor="fav">Favorito</Label>
      </div>

      <fieldset className="grid gap-3">
        <legend className="mb-1 text-sm font-medium">Campos personalizados</legend>
        {fields.map((f, i) => (
          <div key={f.key} className="grid gap-2 rounded-md border p-3">
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Field label={`Nome do campo ${i + 1}`}>
                  {(id) => (
                    <TextInput
                      id={id}
                      value={f.name}
                      onChange={(e) => {
                        dirty(setFields)(
                          fields.map((x) => (x.key === f.key ? { ...x, name: e.target.value } : x)),
                        );
                      }}
                    />
                  )}
                </Field>
              </div>
              <div className="flex items-center gap-2 pb-2">
                <Switch
                  id={`secret-${f.key}`}
                  checked={f.secret}
                  disabled={f.id !== null && f.secret}
                  onCheckedChange={(v) => {
                    dirty(setFields)(
                      fields.map((x) =>
                        x.key === f.key
                          ? {
                              ...x,
                              secret: v,
                              secretUpdate: v ? { kind: "set", value: x.plain } : { kind: "keep" },
                            }
                          : x,
                      ),
                    );
                  }}
                />
                <Label htmlFor={`secret-${f.key}`}>Segredo</Label>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remover campo ${i + 1}`}
                onClick={() => {
                  dirty(setFields)(fields.filter((x) => x.key !== f.key));
                }}
              >
                <Trash2 aria-hidden />
              </Button>
            </div>
            {f.secret ? (
              <SecretEditor
                label={`Valor do campo ${i + 1}`}
                hadValue={f.hadValue}
                update={f.secretUpdate}
                onChange={(u) => {
                  dirty(setFields)(fields.map((x) => (x.key === f.key ? { ...x, secretUpdate: u } : x)));
                }}
                onGenerate={() => void generate(f.key)}
              />
            ) : (
              <Field label={`Valor do campo ${i + 1}`}>
                {(id) => (
                  <TextInput
                    id={id}
                    value={f.plain}
                    onChange={(e) => {
                      dirty(setFields)(
                        fields.map((x) => (x.key === f.key ? { ...x, plain: e.target.value } : x)),
                      );
                    }}
                  />
                )}
              </Field>
            )}
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          className="justify-self-start"
          onClick={() => {
            dirty(setFields)([
              ...fields,
              {
                key: `f${++draftCounter}`,
                id: null,
                name: "",
                secret: false,
                plain: "",
                secretUpdate: { kind: "keep" },
                hadValue: false,
              },
            ]);
          }}
        >
          <Plus aria-hidden /> Adicionar campo
        </Button>
      </fieldset>

      {error ? <Alert kind="error">{error}</Alert> : null}
      <div className="flex gap-2">
        <Button type="submit" disabled={busy}>
          {busy ? "Salvando (cifrando)…" : "Salvar"}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
          Cancelar
        </Button>
      </div>
    </form>
  );
}
