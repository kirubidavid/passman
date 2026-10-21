import { beforeEach, describe, expect, it, vi } from "vitest";
import { getPasswordAgeStatus } from "../../src/rendering";
import { vaultApi } from "../../src/vault-api";
import type { EntryInput } from "../../src/state";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

const entry: EntryInput = {
  id: "smoke-entry",
  title: "Smoke test",
  username: "person@example.com",
  password: "stored secret",
  website: "https://example.com",
  notes: "",
  favorite: false,
  totpSecret: null,
  updatedAt: 0,
  passwordChangedAt: 0,
};

describe("frontend-to-Tauri command contracts", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(undefined);
  });

  it("creates, writes, locks, unlocks, and reads through the command boundary", async () => {
    await vaultApi.create("initial master password");
    await vaultApi.saveEntry(entry);
    await vaultApi.lock();
    await vaultApi.unlock("initial master password");
    await vaultApi.getEntry("smoke-entry");

    expect(invoke.mock.calls).toEqual([
      ["create_vault", { password: "initial master password" }],
      ["save_entry", { entry }],
      ["lock_vault"],
      ["unlock_vault", { password: "initial master password" }],
      ["get_entry", { id: "smoke-entry" }],
    ]);
  });

  it("exports, changes data, restores, and reloads the recovered snapshot", async () => {
    await vaultApi.exportBackup();
    await vaultApi.saveEntry({ ...entry, title: "Changed" });
    await vaultApi.importBackup("initial master password");
    await vaultApi.listEntries();

    expect(invoke.mock.calls).toEqual([
      ["export_backup"],
      ["save_entry", { entry: { ...entry, title: "Changed" } }],
      ["import_backup", { password: "initial master password" }],
      ["list_entries"],
    ]);
  });

  it("changes the master password and sends subsequent unlock attempts separately", async () => {
    await vaultApi.changeMasterPassword(
      "initial master password",
      "replacement master password",
    );
    await vaultApi.lock();
    await vaultApi.unlock("initial master password");
    await vaultApi.unlock("replacement master password");

    expect(invoke.mock.calls).toEqual([
      [
        "change_master_password",
        {
          currentPassword: "initial master password",
          newPassword: "replacement master password",
        },
      ],
      ["lock_vault"],
      ["unlock_vault", { password: "initial master password" }],
      ["unlock_vault", { password: "replacement master password" }],
    ]);
  });

  it("persists the age limit and classifies green, yellow, and red transitions", async () => {
    await vaultApi.setPreferences({ passwordAgeLimitDays: 90 });
    const now = Date.UTC(2026, 0, 1);

    expect(getPasswordAgeStatus(now - 59 * 86_400_000, 90, now).level).toBe(
      "green",
    );
    expect(getPasswordAgeStatus(now - 60 * 86_400_000, 90, now).level).toBe(
      "yellow",
    );
    expect(getPasswordAgeStatus(now - 91 * 86_400_000, 90, now).level).toBe(
      "red",
    );
    expect(invoke).toHaveBeenCalledWith("set_vault_preferences", {
      preferences: { passwordAgeLimitDays: 90 },
    });
  });

  it("keeps authenticated and recovery reset contracts distinct", async () => {
    await vaultApi.authenticatedReset("initial master password", true);
    await vaultApi.recoveryReset("RESET VAULT");

    expect(invoke.mock.calls).toEqual([
      [
        "authenticated_reset_vault",
        {
          currentPassword: "initial master password",
          createBackup: true,
        },
      ],
      ["recovery_reset_vault", { confirmationPhrase: "RESET VAULT" }],
    ]);
  });

  it("generates, retrieves, and deletes SSH keys through explicit commands", async () => {
    await vaultApi.generateSshKey(
      "ssh-1",
      "Production server",
      "deploy key",
      true,
    );
    await vaultApi.getSshKey("ssh-1");
    await vaultApi.storeSshKey(
      "ssh-2",
      "Existing server",
      "ssh-ed25519 public",
      "private",
      "",
      false,
    );
    await vaultApi.deleteSshKey("ssh-1");

    expect(invoke.mock.calls).toEqual([
      [
        "generate_ssh_key",
        {
          id: "ssh-1",
          title: "Production server",
          notes: "deploy key",
          favorite: true,
        },
      ],
      ["get_ssh_key", { id: "ssh-1" }],
      [
        "store_ssh_key",
        {
          id: "ssh-2",
          title: "Existing server",
          publicKey: "ssh-ed25519 public",
          privateKey: "private",
          notes: "",
          favorite: false,
        },
      ],
      ["delete_ssh_key", { id: "ssh-1" }],
    ]);
  });
});
