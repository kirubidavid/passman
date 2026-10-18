import { invoke } from "@tauri-apps/api/core";
import type {
  EntryDetails,
  EntryInput,
  EntrySummary,
  GeneratorOptions,
  Status,
  TotpResult,
  VaultPreferences,
  VaultSnapshot,
} from "./state";

export const vaultApi = {
  status: () => invoke<Status>("vault_status"),
  create: (password: string) =>
    invoke<VaultPreferences>("create_vault", { password }),
  unlock: (password: string) =>
    invoke<VaultPreferences>("unlock_vault", { password }),
  lock: () => invoke<void>("lock_vault"),
  reset: () => invoke<void>("reset_vault"),
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
  exportBackup: () => invoke<string>("export_backup"),
  importBackup: (backup: string, password: string) =>
    invoke<VaultSnapshot>("import_backup", { backup, password }),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<void>("change_master_password", { currentPassword, newPassword }),
};
