import { invoke } from "@tauri-apps/api/core";
import type {
  EntryDetails,
  EntryInput,
  EntrySummary,
  GeneratorOptions,
  Status,
  SshKeyDetails,
  TotpResult,
  VaultPreferences,
  VaultSnapshot,
} from "./state";

export interface ResetResult {
  reset: boolean;
  backupFileName: string | null;
}

export const vaultApi = {
  status: () => invoke<Status>("vault_status"),
  create: (password: string) =>
    invoke<VaultPreferences>("create_vault", { password }),
  unlock: (password: string) =>
    invoke<VaultPreferences>("unlock_vault", { password }),
  lock: () => invoke<void>("lock_vault"),
  authenticatedReset: (currentPassword: string, createBackup: boolean) =>
    invoke<ResetResult>("authenticated_reset_vault", {
      currentPassword,
      createBackup,
    }),
  recoveryReset: (confirmationPhrase: string) =>
    invoke<void>("recovery_reset_vault", { confirmationPhrase }),
  listEntries: () => invoke<VaultSnapshot>("list_entries"),
  setPreferences: (preferences: VaultPreferences) =>
    invoke<VaultPreferences>("set_vault_preferences", { preferences }),
  getEntry: (id: string) => invoke<EntryDetails>("get_entry", { id }),
  getEntryPassword: (id: string) =>
    invoke<string>("get_entry_password", { id }),
  saveEntry: (entry: EntryInput) =>
    invoke<EntrySummary[]>("save_entry", { entry }),
  deleteEntry: (id: string) => invoke<EntrySummary[]>("delete_entry", { id }),
  setTotpSecret: (id: string, secret: string) =>
    invoke<EntrySummary[]>("set_totp_secret", { id, secret }),
  removeTotpSecret: (id: string) =>
    invoke<EntrySummary[]>("remove_totp_secret", { id }),
  getTotpCode: (id: string) => invoke<TotpResult>("get_totp_code", { id }),
  generatePassword: (options: GeneratorOptions) =>
    invoke<string>("generate_password", { options }),
  generateSshKey: (
    id: string,
    title: string,
    notes: string,
    favorite: boolean,
  ) =>
    invoke<VaultSnapshot>("generate_ssh_key", {
      id,
      title,
      notes,
      favorite,
    }),
  storeSshKey: (
    id: string,
    title: string,
    publicKey: string,
    privateKey: string,
    notes: string,
    favorite: boolean,
  ) =>
    invoke<VaultSnapshot>("store_ssh_key", {
      id,
      title,
      publicKey,
      privateKey,
      notes,
      favorite,
    }),
  getSshKey: (id: string) => invoke<SshKeyDetails>("get_ssh_key", { id }),
  deleteSshKey: (id: string) => invoke<VaultSnapshot>("delete_ssh_key", { id }),
  exportBackup: () => invoke<string | null>("export_backup"),
  importBackup: (password: string) =>
    invoke<VaultSnapshot | null>("import_backup", { password }),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<void>("change_master_password", { currentPassword, newPassword }),
  upgradeKdf: (currentPassword: string) =>
    invoke<VaultSnapshot>("upgrade_kdf", { currentPassword }),
};
