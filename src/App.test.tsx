import "@/test/fakeBackend";

import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "@/App";
import { UNLOCK_FAILED } from "@/lib/messages";
import { fake, resetFake, XSS } from "@/test/fakeBackend";

declare global {
  interface Window {
    __xss?: number;
  }
}

beforeEach(() => {
  delete window.__xss;
  vi.useRealTimers();
});

describe("primeiro uso", () => {
  it("exige 15 caracteres, confirmação e ciência da perda irreversível", async () => {
    resetFake("uninitialized");
    fake.handlers.vault_create = () => {
      fake.status = {
        ...fake.status,
        phase: "unlocked",
        generation: 6,
        settings: { autoLockMinutes: 5, clipboardSeconds: 20, lockOnBlur: true },
      };
      return fake.status;
    };
    const user = userEvent.setup();
    render(<App />);
    const create = await screen.findByRole("button", { name: "Criar cofre" });
    expect(screen.getByText(/Não existe recuperação de senha/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Senha mestra"), "curta demais");
    await user.type(screen.getByLabelText("Confirmar senha mestra"), "curta demais");
    expect(create).toBeDisabled();
    await user.clear(screen.getByLabelText("Senha mestra"));
    await user.clear(screen.getByLabelText("Confirmar senha mestra"));
    // Espaços e caracteres não ASCII contam; colagem é permitida.
    await user.click(screen.getByLabelText("Senha mestra"));
    await user.paste("  frase longa ✓ 🔐 ");
    await user.click(screen.getByLabelText("Confirmar senha mestra"));
    await user.paste("  frase longa ✓ 🔐 ");
    expect(create).toBeDisabled();
    await user.click(screen.getByRole("checkbox"));
    expect(create).toBeEnabled();
    await user.click(create);
    await waitFor(() => {
      expect(fake.calls.find((c) => c.cmd === "vault_create")?.args).toEqual({
        password: "  frase longa ✓ 🔐 ",
        confirmation: "  frase longa ✓ 🔐 ",
      });
    });
  });
});

describe("desbloqueio", () => {
  it("mostra a mensagem genérica e o atraso progressivo", async () => {
    resetFake("locked");
    fake.handlers.vault_unlock = () => {
      throw { code: "authentication_failed", retryAfterMs: 2000 };
    };
    const user = userEvent.setup();
    render(<App />);
    await user.type(await screen.findByLabelText("Senha mestra"), "senha errada qualquer");
    await user.click(screen.getByRole("button", { name: "Desbloquear" }));
    expect(await screen.findByText(UNLOCK_FAILED)).toBeInTheDocument();
    expect(screen.getByText(/Nova tentativa disponível em/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Desbloquear" })).toBeDisabled();
    // O campo de senha é limpo após a falha.
    expect(screen.getByLabelText("Senha mestra")).toHaveValue("");
  });
});

describe("cofre desbloqueado", () => {
  beforeEach(() => {
    resetFake("unlocked");
  });

  it("exibe conteúdo hostil apenas como texto (XSS inerte)", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Entradas" });
    await within(nav).findByText(XSS);
    await user.click(within(nav).getByRole("button", { name: /Favorito/ }));
    await screen.findByRole("heading", { name: /Favorito/ });
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    // URL é texto, não link.
    expect(screen.getByText("javascript:window.__xss=3").closest("a")).toBeNull();
    expect(window.__xss).toBeUndefined();
  });

  it("revela por no máximo 15 s, remascara ao perder foco e copia sem receber o segredo", async () => {
    vi.spyOn(document, "hasFocus").mockReturnValue(true);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Entradas" });
    await user.click(await within(nav).findByRole("button", { name: /Favorito/ }));
    await screen.findByRole("heading", { name: /Favorito/ });

    await user.click(screen.getByRole("button", { name: /Revelar Senha/ }));
    expect(await screen.findByText("segredo-revelado-ficticio")).toBeInTheDocument();
    // Segredo nunca em atributos.
    expect(document.body.innerHTML.match(/(aria-label|title)="[^"]*segredo-revelado/)).toBeNull();
    act(() => {
      vi.advanceTimersByTime(15_001);
    });
    expect(screen.queryByText("segredo-revelado-ficticio")).toBeNull();

    await user.click(screen.getByRole("button", { name: /Revelar Senha/ }));
    expect(await screen.findByText("segredo-revelado-ficticio")).toBeInTheDocument();
    act(() => {
      window.dispatchEvent(new Event("blur"));
    });
    expect(screen.queryByText("segredo-revelado-ficticio")).toBeNull();

    await user.click(screen.getByRole("button", { name: /Copiar Senha/ }));
    expect(await screen.findByText(/Senha copiado\(a\)/)).toBeInTheDocument();
    const copyCall = fake.calls.find((c) => c.cmd === "entry_copy_secret");
    expect(copyCall?.args).toMatchObject({ secret: { kind: "password" } });
  });

  it("bloqueio imposto pelo Rust desmonta o cofre e limpa a UI", async () => {
    const user = userEvent.setup();
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Entradas" });
    await user.click(await within(nav).findByRole("button", { name: /Favorito/ }));
    await screen.findByRole("heading", { name: /Favorito/ });
    act(() => {
      fake.emitLocked("inactivity");
    });
    expect(await screen.findByText("Cofre bloqueado por inatividade.")).toBeInTheDocument();
    expect(screen.queryByText(XSS)).toBeNull();
    expect(screen.queryByText("usuario.ficticio")).toBeNull();
  });

  it("descarta respostas de uma sessão antiga", async () => {
    let resolveList: ((v: unknown) => void) | undefined;
    fake.handlers.entries_list = () =>
      new Promise((r) => {
        resolveList = r;
      });
    render(<App />);
    await waitFor(() => {
      expect(resolveList).toBeDefined();
    });
    // Resposta tardia marcada com outra geração: ignorada.
    await act(async () => {
      resolveList?.({
        generation: 999,
        entries: [{ id: "cc".repeat(16), title: "tardia", username: "", favorite: false, updatedAtMs: 1 }],
      });
      await Promise.resolve();
    });
    expect(screen.queryByText("tardia")).toBeNull();
  });

  it("erro 'locked' em qualquer chamada volta à tela de bloqueio", async () => {
    fake.handlers.entry_get = () => {
      fake.status = { ...fake.status, phase: "locked", generation: 9, settings: null };
      throw { code: "locked" };
    };
    const user = userEvent.setup();
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Entradas" });
    await user.click(await within(nav).findByRole("button", { name: /Favorito/ }));
    expect(await screen.findByRole("button", { name: "Desbloquear" })).toBeInTheDocument();
  });

  it("não usa armazenamento persistente do navegador", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    render(<App />);
    const nav = await screen.findByRole("navigation", { name: "Entradas" });
    await user.click(await within(nav).findByRole("button", { name: /Favorito/ }));
    await screen.findByRole("heading", { name: /Favorito/ });
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});
