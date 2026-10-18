import { beforeEach, describe, expect, it, vi } from "vitest";

const vaultApi = vi.hoisted(() => ({
  create: vi.fn(),
  unlock: vi.fn(),
}));
const confirmAction = vi.hoisted(() => vi.fn());
vi.mock("../../src/vault-api", () => ({ vaultApi }));
vi.mock("../../src/clipboard", () => ({ copyText: vi.fn() }));
vi.mock("../../src/generator", () => ({ generatePassword: vi.fn() }));
vi.mock("../../src/modal", () => ({
  confirmAction,
  openEntryModal: vi.fn(),
  openVaultSettings: vi.fn(),
  showTotp: vi.fn(),
}));

import {
  authView,
  configureRendering,
  dashboardShell,
  renderEntries,
} from "../../src/rendering";
import { state } from "../../src/state";

describe("vault rendering", () => {
  const callbacks = {
    loadDashboard: vi.fn<() => Promise<void>>(),
    resetVault: vi.fn<() => Promise<void>>(),
    lockVault: vi.fn<() => Promise<void>>(),
    startAutoLock: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = '<div id="app"></div><div id="toast"></div>';
    configureRendering(callbacks);
    state.entries = [
      {
        id: "mail",
        title: "Personal Mail",
        username: "person@example.com",
        website: "mail.example.com",
        favorite: true,
        hasTotp: false,
        updatedAt: 2,
      },
      {
        id: "bank",
        title: "Bank",
        username: "customer",
        website: "bank.example.com",
        favorite: false,
        hasTotp: false,
        updatedAt: 1,
      },
    ];
    state.activeFilter = "All items";
    state.searchTerm = "";
  });

  it("filters entries using title, username, or website text", () => {
    dashboardShell();
    renderEntries();
    const search = document.querySelector<HTMLInputElement>("#search-input");
    if (!search) throw new Error("Search input was not rendered");

    search.value = "person@example";
    search.dispatchEvent(new Event("input", { bubbles: true }));

    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Personal Mail",
    );
    expect(document.querySelector("#entries-area")?.textContent).not.toContain(
      "Bank",
    );
    expect(document.querySelector("#heading-count")?.textContent).toBe("1");
  });

  it("shows an empty search result instead of stale entries", () => {
    dashboardShell();
    const search = document.querySelector<HTMLInputElement>("#search-input");
    if (!search) throw new Error("Search input was not rendered");

    search.value = "not-present";
    search.dispatchEvent(new Event("input", { bubbles: true }));

    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "No matching passwords",
    );
    expect(document.querySelector("#section-count")?.textContent).toBe("0");
  });

  it("surfaces unlock errors and re-enables the submit button", async () => {
    vaultApi.unlock.mockRejectedValue(
      new Error("Master password is incorrect"),
    );
    authView(true);
    const form = document.querySelector<HTMLFormElement>("#auth-form");
    const password =
      document.querySelector<HTMLInputElement>("#master-password");
    const submit = document.querySelector<HTMLButtonElement>(".auth-submit");
    if (!form || !password || !submit)
      throw new Error("Unlock form was not rendered");
    password.value = "incorrect password";

    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await vi.waitFor(() => {
      expect(document.querySelector("#auth-error")?.textContent).toBe(
        "Master password is incorrect",
      );
    });

    expect(submit.disabled).toBe(false);
    expect(callbacks.loadDashboard).not.toHaveBeenCalled();
  });

  it("requires the reset-vault phrase dialog before resetting", async () => {
    confirmAction.mockResolvedValue(true);
    callbacks.resetVault.mockResolvedValue();
    authView(true);

    expect(document.querySelector("#modal-root")).not.toBeNull();
    document.querySelector<HTMLButtonElement>("#reset-vault")?.click();

    await vi.waitFor(() => expect(callbacks.resetVault).toHaveBeenCalledOnce());
    expect(confirmAction).toHaveBeenCalledWith(
      expect.objectContaining({
        confirmLabel: "Reset vault permanently",
        phrase: "RESET VAULT",
      }),
    );
  });
});
