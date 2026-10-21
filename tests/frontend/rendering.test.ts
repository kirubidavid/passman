import { beforeEach, describe, expect, it, vi } from "vitest";

const vaultApi = vi.hoisted(() => ({
  create: vi.fn(),
  unlock: vi.fn(),
}));
const confirmAction = vi.hoisted(() => vi.fn());
const confirmPhraseAction = vi.hoisted(() => vi.fn());
vi.mock("../../src/vault-api", () => ({ vaultApi }));
vi.mock("../../src/clipboard", () => ({ copyText: vi.fn() }));
vi.mock("../../src/generator", () => ({ generatePassword: vi.fn() }));
vi.mock("../../src/modal", () => ({
  confirmAction,
  confirmPhraseAction,
  openEntryModal: vi.fn(),
  openSshKeyDetails: vi.fn(),
  openSshKeyModal: vi.fn(),
  openVaultSettings: vi.fn(),
  showTotp: vi.fn(),
}));

import {
  authView,
  configureRendering,
  dashboardShell,
  getEntryHealth,
  getPasswordAgeStatus,
  renderEntries,
  setFilter,
} from "../../src/rendering";
import { getPasswordAgeLimitDays, state } from "../../src/state";

describe("vault rendering", () => {
  const callbacks = {
    loadDashboard: vi.fn<() => Promise<void>>(),
    recoveryResetVault: vi.fn<(confirmationPhrase: string) => Promise<void>>(),
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
        passwordChangedAt: Date.now(),
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
      {
        id: "bank",
        title: "Bank",
        username: "customer",
        website: "bank.example.com",
        favorite: false,
        hasTotp: false,
        updatedAt: 1,
        passwordChangedAt: Date.now(),
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
    ];
    state.activeFilter = "All items";
    state.sshKeys = [];
    state.searchTerm = "";
    state.securityUpgradeAvailable = false;
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
      "No matching vault items",
    );
    expect(document.querySelector("#section-count")?.textContent).toBe("0");
  });

  it("shows a security-upgrade notice for outdated KDF parameters", () => {
    state.securityUpgradeAvailable = true;

    dashboardShell();

    expect(
      document.querySelector("#security-upgrade-banner")?.textContent,
    ).toContain("Security upgrade available.");
  });

  it("renders SSH metadata without exposing key material", () => {
    state.entries = [];
    state.sshKeys = [
      {
        id: "ssh-1",
        title: "Production server",
        algorithm: "Ed25519",
        fingerprint: "SHA256:test",
        favorite: false,
        createdAt: 1,
        updatedAt: 1,
      },
    ];

    dashboardShell();
    setFilter("SSH keys");

    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Production server",
    );
    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "SHA256:test",
    );
    expect(document.querySelector("#entries-area")?.textContent).not.toContain(
      "PRIVATE KEY",
    );
  });

  it("uses green, yellow, and red password-age thresholds", () => {
    const now = 200 * 86_400_000;

    expect(getPasswordAgeStatus(now - 59 * 86_400_000, 90, now).level).toBe(
      "green",
    );
    expect(getPasswordAgeStatus(now - 60 * 86_400_000, 90, now).level).toBe(
      "yellow",
    );
    expect(getPasswordAgeStatus(now - 91 * 86_400_000, 90, now).level).toBe(
      "red",
    );
  });

  it("shows legacy password age as unknown and labels the fallback as estimated", () => {
    const now = 200 * 86_400_000;
    const health = getEntryHealth(
      {
        id: "legacy",
        title: "Legacy password",
        username: "",
        website: "",
        favorite: false,
        hasTotp: false,
        updatedAt: now - 100 * 86_400_000,
        passwordChangedAt: 0,
        passwordAgeTrackingStartedAt: now - 10 * 86_400_000,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
      90,
      now,
    );

    expect(health.age.label).toBe("Age unknown");
    expect(health.age.estimated).toBe(true);
    expect(health.age.level).toBe("red");
    expect(health.age.estimateLabel).toBe("Estimated overdue");
    expect(health.age.description).toContain("Age tracking began");
    expect(health.age.description).toContain(
      "Estimated age: 100 days based on the entry's last update.",
    );

    state.entries = [
      {
        id: "legacy",
        title: "Legacy password",
        username: "",
        website: "",
        favorite: false,
        hasTotp: false,
        updatedAt: now - 100 * 86_400_000,
        passwordChangedAt: 0,
        passwordAgeTrackingStartedAt: now - 10 * 86_400_000,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
    ];
    vi.setSystemTime(now);
    dashboardShell();
    renderEntries();

    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Age unknown",
    );
    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Estimated overdue",
    );
  });

  it("counts health issues and sorts the health filter by urgency", () => {
    const now = Date.now();
    const base = {
      username: "",
      website: "",
      favorite: false,
      hasTotp: false,
      updatedAt: now,
    };
    state.entries = [
      {
        ...base,
        id: "due",
        title: "Due soon",
        passwordChangedAt: now - 60 * 86_400_000,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
      {
        ...base,
        id: "weak",
        title: "Weak password",
        passwordChangedAt: now,
        passwordStrengthScore: 2,
        duplicatePassword: false,
      },
      {
        ...base,
        id: "duplicate-one",
        title: "Duplicate one",
        passwordChangedAt: now,
        passwordStrengthScore: 4,
        duplicatePassword: true,
      },
      {
        ...base,
        id: "expired",
        title: "Expired password",
        passwordChangedAt: now - 91 * 86_400_000,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
      {
        ...base,
        id: "duplicate-two",
        title: "Duplicate two",
        passwordChangedAt: now,
        passwordStrengthScore: 4,
        duplicatePassword: true,
      },
      {
        ...base,
        id: "healthy",
        title: "Healthy password",
        passwordChangedAt: now,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
    ];
    dashboardShell();
    setFilter("Password health");

    expect(document.querySelector("#health-expired-count")?.textContent).toBe(
      "1",
    );
    expect(document.querySelector("#health-due-count")?.textContent).toBe("1");
    expect(document.querySelector("#health-duplicate-count")?.textContent).toBe(
      "2",
    );
    expect(document.querySelector("#health-weak-count")?.textContent).toBe("1");
    const titles = [
      ...document.querySelectorAll<HTMLElement>(".entry-title-row h3"),
    ].map((element) => element.textContent);
    expect(titles[0]).toBe("Expired password");
    expect(titles).not.toContain("Healthy password");
    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Duplicate",
    );
    expect(document.querySelector("#entries-area")?.textContent).toContain(
      "Weak (2/4)",
    );
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

  it("applies encrypted preferences returned during unlock", async () => {
    vaultApi.unlock.mockResolvedValue({ passwordAgeLimitDays: 180 });
    callbacks.loadDashboard.mockResolvedValue();
    authView(true);
    const form = document.querySelector<HTMLFormElement>("#auth-form");
    const password =
      document.querySelector<HTMLInputElement>("#master-password");
    if (!form || !password) throw new Error("Unlock form was not rendered");
    password.value = "correct password";

    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );

    await vi.waitFor(() =>
      expect(callbacks.loadDashboard).toHaveBeenCalledOnce(),
    );
    expect(getPasswordAgeLimitDays()).toBe(180);
  });

  it("requires the reset-vault phrase dialog before resetting", async () => {
    confirmPhraseAction.mockResolvedValue("RESET VAULT");
    callbacks.recoveryResetVault.mockResolvedValue();
    authView(true);

    expect(document.querySelector("#modal-root")).not.toBeNull();
    document.querySelector<HTMLButtonElement>("#reset-vault")?.click();

    await vi.waitFor(() =>
      expect(callbacks.recoveryResetVault).toHaveBeenCalledWith("RESET VAULT"),
    );
    expect(confirmPhraseAction).toHaveBeenCalledWith(
      expect.objectContaining({
        confirmLabel: "Recovery reset permanently",
        phrase: "RESET VAULT",
      }),
    );
  });
});
