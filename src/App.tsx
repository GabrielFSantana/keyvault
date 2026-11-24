import { useCallback, useEffect, useRef, useState } from "react";

import { Alert } from "@/components/common";
import { UnlockScreen } from "@/components/UnlockScreen";
import { VaultView } from "@/components/VaultView";
import { Welcome } from "@/components/Welcome";
import { api, type Status } from "@/lib/api";
import { errorMessage, lockReasonMessage } from "@/lib/messages";

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  // Primeiro uso: oferecer backup criptografado logo após criar o cofre.
  const [offerBackup, setOfferBackup] = useState(false);
  const generation = useRef(0);

  const apply = useCallback((s: Status) => {
    generation.current = s.generation;
    setStatus(s);
    if (s.phase !== "unlocked") setNotice(lockReasonMessage(s.lastLockReason));
    else setNotice(null);
  }, []);

  const refresh = useCallback(async () => {
    try {
      apply(await api.status());
      setFatal(null);
    } catch (e) {
      setFatal(errorMessage(e));
    }
  }, [apply]);

  useEffect(() => {
    api
      .status()
      .then(apply)
      .catch((e: unknown) => {
        setFatal(errorMessage(e));
      });
    const unlisten = api.onLocked(() => {
      // Bloqueio imposto pelo Rust (inatividade, foco, SO): a árvore do cofre é desmontada.
      void refresh();
    });
    // Sem menu de contexto do WebView (recarregar/imprimir/salvar página).
    const noMenu = (e: MouseEvent) => {
      e.preventDefault();
    };
    window.addEventListener("contextmenu", noMenu);
    return () => {
      window.removeEventListener("contextmenu", noMenu);
      void unlisten.then((f) => {
        f();
      });
    };
  }, [apply, refresh]);

  const lock = useCallback(() => {
    // Limpa a UI imediatamente; o Rust incrementa a geração e zera o cofre.
    setStatus((s) => (s ? { ...s, phase: "locking", settings: null, entryCount: null } : s));
    void api
      .lock()
      .then(apply)
      .catch(() => void refresh());
  }, [apply, refresh]);

  if (fatal) {
    return (
      <main className="mx-auto max-w-md p-6">
        <Alert kind="error">{fatal}</Alert>
      </main>
    );
  }
  if (!status) {
    return (
      <main className="p-6" aria-busy="true">
        Carregando…
      </main>
    );
  }
  if (status.phase === "uninitialized")
    return (
      <Welcome
        onStatus={apply}
        onCreated={(s) => {
          setOfferBackup(true);
          apply(s);
        }}
      />
    );
  if (status.phase === "unlocked") {
    return (
      <VaultView
        key={status.generation}
        status={status}
        onStatus={apply}
        onLock={lock}
        onSessionEnded={() => void refresh()}
        offerBackup={offerBackup}
        onBackupOffered={() => {
          setOfferBackup(false);
        }}
      />
    );
  }
  return (
    <UnlockScreen key={status.selectedVaultId ?? "none"} status={status} notice={notice} onStatus={apply} />
  );
}
