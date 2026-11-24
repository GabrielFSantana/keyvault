import { isIpcError, type LockReason } from "./api";

export const UNLOCK_FAILED = "Não foi possível desbloquear: senha incorreta ou cofre inválido";

const FIELD_NAMES: Record<string, string> = {
  title: "Título",
  url: "URL",
  username: "Usuário",
  password: "Senha",
  notes: "Notas",
  tags: "Tags",
  tag: "Tag",
  custom_fields: "Campos personalizados",
  custom_field_name: "Nome do campo personalizado",
  custom_field_value: "Valor do campo personalizado",
  entries: "Entradas",
  master_password: "Senha mestra",
  master_password_confirmation: "Confirmação da senha mestra",
  settings: "Preferências",
  generator_options: "Opções do gerador",
  id: "Identificador",
  current_password: "Senha atual",
};

function seconds(ms: number | undefined): number {
  return Math.max(1, Math.ceil((ms ?? 0) / 1000));
}

/** Mensagem em português para um erro de IPC. Nunca reproduz conteúdo do usuário. */
export function errorMessage(e: unknown): string {
  if (!isIpcError(e)) return "Ocorreu um erro inesperado. Tente novamente.";
  switch (e.code) {
    case "authentication_failed":
      if (e.field === "current_password") return "A senha atual está incorreta.";
      return UNLOCK_FAILED;
    case "too_many_attempts":
      return `Muitas tentativas. Aguarde ${seconds(e.retryAfterMs)} s e tente novamente.`;
    case "validation": {
      if (e.field === "master_password")
        return "A senha mestra deve ter de 15 caracteres a 1.024 bytes (UTF-8).";
      if (e.field === "master_password_confirmation") return "A confirmação não corresponde à senha.";
      if (e.field === "generator_options")
        return "Opções do gerador inválidas (16 a 128 caracteres, ao menos uma classe).";
      const name = e.field ? FIELD_NAMES[e.field] : undefined;
      return name ? `Valor inválido em: ${name}.` : "Valor inválido.";
    }
    case "locked":
    case "stale_session":
      return "O cofre foi bloqueado.";
    case "not_found":
      return "Item não encontrado.";
    case "vault_busy":
      return "O cofre está em uso por outro processo do KeyVault.";
    case "storage_full":
      return "Sem espaço em disco. Nada foi alterado; libere espaço e tente novamente.";
    case "permission_denied":
      return "Permissão negada ao acessar o arquivo. Nada foi alterado.";
    case "revision_conflict":
      return "O cofre foi alterado por outra gravação. Nada foi salvo; tente novamente.";
    case "invalid_file":
      return "O arquivo não é um backup válido do KeyVault.";
    case "invalid_state":
      return "Operação indisponível neste momento.";
    case "already_exists":
      return "O destino já existe.";
    case "clipboard_unavailable":
      return "Não foi possível acessar a área de transferência.";
    case "rng_failure":
      return "Falha na fonte de aleatoriedade do sistema. A operação foi cancelada sem gravar nada.";
    case "kdf_failure":
      return "Falha ao derivar a chave (memória insuficiente?). Nada foi alterado.";
    case "forbidden_origin":
      return "Chamada recusada.";
    default:
      return "Não foi possível concluir a operação. Nada foi alterado.";
  }
}

export function lockReasonMessage(r: LockReason | null): string | null {
  switch (r) {
    case "inactivity":
      return "Cofre bloqueado por inatividade.";
    case "focusLost":
      return "Cofre bloqueado após 30 segundos fora de foco.";
    case "osLock":
      return "Cofre bloqueado porque a sessão do Windows foi bloqueada.";
    case "suspend":
      return "Cofre bloqueado porque o computador entrou em suspensão.";
    case "userSwitch":
      return "Cofre bloqueado por troca de usuário.";
    case "shutdown":
      return "Cofre bloqueado por encerramento da sessão.";
    case "restore":
      return "Backup restaurado como novo cofre. Desbloqueie-o com a nova senha.";
    case "manual":
      return "Cofre bloqueado.";
    default:
      return null;
  }
}

export function formatDate(ms: number): string {
  return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(new Date(ms));
}

export function shortId(id: string): string {
  return `${id.slice(0, 4)}…${id.slice(-4)}`;
}
