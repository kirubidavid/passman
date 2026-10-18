import { beforeEach, describe, expect, it, vi } from "vitest";

const vaultApi = vi.hoisted(() => ({
  authenticatedReset: vi.fn(),
  exportBackup: vi.fn(),
  getTotpCode: vi.fn(),
  importBackup: vi.fn(),
  setPreferences: vi.fn(),
  upgradeKdf: vi.fn(),
}));
vi.mock("../../src/vault-api", () => ({ vaultApi }));
vi.mock("../../src/clipboard", () => ({ copyText: vi.fn() }));
vi.mock("../../src/generator", () => ({ generatePassword: vi.fn() }));

import {
  closeModal,
  configureModal,
  confirmAction,
  confirmPhraseAction,
  openVaultSettings,
  showTotp,
} from "../../src/modal";
import { getPasswordAgeLimitDays, state } from "../../src/state";

describe("modal cleanup", () => {
  const completeVaultReset = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML =
      '<input id="search-input" /><div id="modal-root"></div><div id="toast"></div>';
    state.entries = [
      {
        id: "entry-1",
        title: "Mail",
        username: "",
        website: "",
        favorite: false,
        hasTotp: true,
        updatedAt: 1,
        passwordChangedAt: 1,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
    ];
    state.securityUpgradeAvailable = false;
    vaultApi.getTotpCode.mockResolvedValue({
      code: "123456",
      secondsRemaining: 20,
    });
    configureModal({
      setFilter: vi.fn(),
      renderEntries: vi.fn(),
      recordActivity: vi.fn(),
      completeVaultReset,
    });
  });

  it("closes on Escape and stops the TOTP refresh interval", async () => {
    await showTotp("entry-1");
    expect(document.querySelector("#totp-code")?.textContent).toBe("123456");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await vi.advanceTimersByTimeAsync(3_000);

    expect(document.querySelector("#modal-root")?.children).toHaveLength(0);
    expect(vaultApi.getTotpCode).toHaveBeenCalledOnce();
  });

  it("stops queued refresh work when modal content is removed", async () => {
    await showTotp("entry-1");
    closeModal();

    await vi.advanceTimersByTimeAsync(1_000);

    expect(vaultApi.getTotpCode).toHaveBeenCalledOnce();
  });

  it("shows backend errors without leaving a partial dialog", async () => {
    vaultApi.getTotpCode.mockRejectedValue(
      new Error("Authenticator unavailable"),
    );

    await showTotp("entry-1");

    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.querySelector("#toast")?.textContent).toBe(
      "Authenticator unavailable",
    );
    expect(document.querySelector("#toast")?.classList.contains("error")).toBe(
      true,
    );
  });

  it("requires the exact reset phrase before enabling a destructive action", async () => {
    const confirmed = confirmAction({
      title: "Permanently reset this vault?",
      description: "Every saved password will be deleted.",
      confirmLabel: "Reset vault permanently",
      phrase: "RESET VAULT",
    });
    const input = document.querySelector<HTMLInputElement>(
      ".confirmation-phrase input",
    );
    const button = document.querySelector<HTMLButtonElement>(".button-danger");
    if (!input || !button)
      throw new Error("Confirmation dialog was not rendered");

    expect(document.querySelector('[role="alertdialog"]')).not.toBeNull();
    expect(button.disabled).toBe(true);
    input.value = "reset vault";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    expect(button.disabled).toBe(true);

    input.value = "RESET VAULT";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    expect(button.disabled).toBe(false);
    button.click();

    await expect(confirmed).resolves.toBe(true);
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it("treats Escape as cancellation for confirmation dialogs", async () => {
    const confirmed = confirmAction({
      title: "Delete password?",
      description: "This cannot be undone.",
      confirmLabel: "Delete password",
    });

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));

    await expect(confirmed).resolves.toBe(false);
    expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it("returns the exact typed recovery phrase for Rust verification", async () => {
    const confirmation = confirmPhraseAction({
      title: "Recovery reset?",
      description: "This deletes the encrypted vault.",
      confirmLabel: "Recovery reset",
      phrase: "RESET VAULT",
    });
    const input = document.querySelector<HTMLInputElement>(
      ".confirmation-phrase input",
    );
    if (!input) throw new Error("Confirmation phrase input was not rendered");
    input.value = "RESET VAULT";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>(".button-danger")?.click();

    await expect(confirmation).resolves.toBe("RESET VAULT");
  });

  it("persists password age preferences through the vault API", async () => {
    vaultApi.setPreferences.mockResolvedValue({
      passwordAgeLimitDays: 120,
    });
    openVaultSettings();
    const input = document.querySelector<HTMLInputElement>(
      "#password-age-limit",
    );
    if (!input) throw new Error("Password age preference was not rendered");

    input.value = "120";
    input.dispatchEvent(new Event("change", { bubbles: true }));

    await vi.waitFor(() =>
      expect(vaultApi.setPreferences).toHaveBeenCalledWith({
        passwordAgeLimitDays: 120,
      }),
    );
    expect(getPasswordAgeLimitDays()).toBe(120);
  });

  it("keeps settings open when the native export dialog is cancelled", async () => {
    vaultApi.exportBackup.mockResolvedValue(null);
    openVaultSettings();

    document.querySelector<HTMLButtonElement>("#export-backup")?.click();

    await vi.waitFor(() => expect(vaultApi.exportBackup).toHaveBeenCalledOnce());
    expect(document.querySelector(".vault-settings-modal")).not.toBeNull();
  });

  it("restores through the Rust file picker without reading a browser File", async () => {
    vaultApi.importBackup.mockResolvedValue({
      entries: [],
      preferences: { passwordAgeLimitDays: 90 },
    });
    openVaultSettings();
    document.querySelector<HTMLButtonElement>("#restore-backup")?.click();

    expect(document.querySelector('input[type="file"]')).toBeNull();
    const password =
      document.querySelector<HTMLInputElement>("#backup-password");
    if (!password) throw new Error("Backup password input was not rendered");
    password.value = "backup password";
    document
      .querySelector<HTMLFormElement>("#restore-form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    document.querySelector<HTMLButtonElement>(".button-danger")?.click();

    await vi.waitFor(() =>
      expect(vaultApi.importBackup).toHaveBeenCalledWith("backup password"),
    );
  });

  it("requires the current password for reset and requests a final backup", async () => {
    vaultApi.authenticatedReset.mockResolvedValue({
      reset: true,
      backupFileName: "final.passman",
    });
    openVaultSettings();
    document.querySelector<HTMLButtonElement>("#authenticated-reset")?.click();
    const password =
      document.querySelector<HTMLInputElement>("#reset-master-password");
    if (!password) throw new Error("Reset password input was not rendered");
    password.value = "current password";

    document
      .querySelector<HTMLFormElement>("#authenticated-reset-form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() =>
      expect(vaultApi.authenticatedReset).toHaveBeenCalledWith(
        "current password",
        true,
      ),
    );
    expect(completeVaultReset).toHaveBeenCalledWith("final.passman");
  });

  it("requires the master password before upgrading KDF parameters", async () => {
    state.securityUpgradeAvailable = true;
    vaultApi.upgradeKdf.mockResolvedValue({
      entries: state.entries,
      preferences: { passwordAgeLimitDays: 90 },
      securityUpgradeAvailable: false,
    });
    openVaultSettings();
    document.querySelector<HTMLButtonElement>("#upgrade-kdf")?.click();
    const password =
      document.querySelector<HTMLInputElement>("#kdf-upgrade-password");
    if (!password) throw new Error("KDF upgrade password input was not rendered");
    password.value = "current password";

    document
      .querySelector<HTMLFormElement>("#kdf-upgrade-form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() =>
      expect(vaultApi.upgradeKdf).toHaveBeenCalledWith("current password"),
    );
    expect(state.securityUpgradeAvailable).toBe(false);
  });
});
