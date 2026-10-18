import { copyText } from "./clipboard";
import { generatePassword } from "./generator";
import {
  AUTO_LOCK_OPTIONS,
  MAX_PASSWORD_AGE_LIMIT_DAYS,
  MIN_PASSWORD_AGE_LIMIT_DAYS,
  applyVaultSnapshot,
  getAutoLockMinutes,
  getPasswordAgeLimitDays,
  setAutoLockMinutes,
  setPasswordAgeLimitDays,
  state,
  type EntryDetails,
  type EntryInput,
} from "./state";
import { $, escapeHtml, fail, icon, toast } from "./ui";
import { vaultApi } from "./vault-api";

interface ModalCallbacks {
  setFilter(filter: string): void;
  renderEntries(): void;
  recordActivity(): void;
  completeVaultReset(backupFileName?: string | null): void;
}

let callbacks: ModalCallbacks;
let totpRefreshTimer = 0;
let activeDialog: HTMLElement | null = null;
let activeDialogDismiss: (() => void) | null = null;
let restoreFocusTo: HTMLElement | null = null;
let pendingConfirmationCancel: (() => void) | null = null;

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type=hidden])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export function configureModal(next: ModalCallbacks) {
  callbacks = next;
}

function stopTotpRefresh() {
  window.clearInterval(totpRefreshTimer);
  totpRefreshTimer = 0;
}

function dialogKeydown(event: KeyboardEvent) {
  if (!activeDialog) return;
  if (event.key === "Escape") {
    event.preventDefault();
    if (activeDialogDismiss) activeDialogDismiss();
    else closeModal();
    return;
  }
  if (event.key !== "Tab") return;
  const focusable = [
    ...activeDialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
  ].filter((element) => element.getClientRects().length > 0);
  if (focusable.length === 0) {
    event.preventDefault();
    activeDialog.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (
    event.shiftKey &&
    (document.activeElement === first ||
      !activeDialog.contains(document.activeElement))
  ) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function activateDialog(
  dialogSelector: string,
  initialFocusSelector?: string,
  dismiss?: () => void,
) {
  if (!activeDialog) {
    restoreFocusTo =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
  }
  activeDialog = $<HTMLElement>(dialogSelector);
  activeDialogDismiss = dismiss ?? null;
  document.removeEventListener("keydown", dialogKeydown);
  document.addEventListener("keydown", dialogKeydown);
  const initialFocus = initialFocusSelector
    ? activeDialog.querySelector<HTMLElement>(initialFocusSelector)
    : activeDialog.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
  requestAnimationFrame(() => (initialFocus ?? activeDialog)?.focus());
}

export function closeModal() {
  pendingConfirmationCancel?.();
  pendingConfirmationCancel = null;
  stopTotpRefresh();
  document.removeEventListener("keydown", dialogKeydown);
  document.querySelector<HTMLElement>("#modal-root")?.replaceChildren();
  state.passwordVisible = false;
  activeDialog = null;
  activeDialogDismiss = null;
  const focusTarget = restoreFocusTo;
  restoreFocusTo = null;
  requestAnimationFrame(() => {
    if (focusTarget?.isConnected) focusTarget.focus();
  });
}

interface ConfirmationOptions {
  title: string;
  description: string;
  confirmLabel: string;
  phrase?: string;
  onConfirmedPhrase?: (phrase: string) => void;
}

export function confirmAction(options: ConfirmationOptions): Promise<boolean> {
  const parentDialog = activeDialog;
  const parentDismiss = activeDialogDismiss;
  const parentFocus =
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  const confirmationId = `confirmation-${crypto.randomUUID()}`;
  const phraseId = `${confirmationId}-phrase`;
  $("#modal-root").insertAdjacentHTML(
    "beforeend",
    `<div class="modal-backdrop confirmation-backdrop" id="${confirmationId}-backdrop"><section class="entry-modal confirmation-modal" id="${confirmationId}" role="alertdialog" aria-modal="true" aria-labelledby="${confirmationId}-title" aria-describedby="${confirmationId}-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">CONFIRM DESTRUCTIVE ACTION</p><h2 id="${confirmationId}-title">${escapeHtml(options.title)}</h2></div><button class="icon-button" id="${confirmationId}-close" type="button" aria-label="Close">${icon("close", 19)}</button></div><p class="dialog-description" id="${confirmationId}-description">${escapeHtml(options.description)}</p>${options.phrase ? `<label class="confirmation-phrase" for="${phraseId}">Type <strong>${escapeHtml(options.phrase)}</strong> to continue<input id="${phraseId}" type="text" autocomplete="off" spellcheck="false" /></label>` : ""}<div class="modal-footer"><button type="button" class="button button-quiet" id="${confirmationId}-cancel">Cancel</button><button type="button" class="button button-danger" id="${confirmationId}-confirm" ${options.phrase ? "disabled" : ""}>${escapeHtml(options.confirmLabel)}</button></div></section></div>`,
  );

  return new Promise((resolve) => {
    let settled = false;
    const finish = (confirmed: boolean) => {
      if (settled) return;
      settled = true;
      pendingConfirmationCancel = null;
      document.querySelector(`#${confirmationId}-backdrop`)?.remove();
      activeDialog = parentDialog?.isConnected ? parentDialog : null;
      activeDialogDismiss = activeDialog ? parentDismiss : null;
      if (!activeDialog) {
        document.removeEventListener("keydown", dialogKeydown);
        restoreFocusTo = null;
      }
      requestAnimationFrame(() => {
        if (parentFocus?.isConnected) parentFocus.focus();
      });
      resolve(confirmed);
    };
    pendingConfirmationCancel = () => finish(false);
    const confirm = $<HTMLButtonElement>(`#${confirmationId}-confirm`);
    document
      .querySelector(`#${confirmationId}-close`)
      ?.addEventListener("click", () => finish(false));
    document
      .querySelector(`#${confirmationId}-cancel`)
      ?.addEventListener("click", () => finish(false));
    $(`#${confirmationId}-backdrop`).addEventListener("click", (event) => {
      if (event.target === event.currentTarget) finish(false);
    });
    document
      .querySelector<HTMLInputElement>(`#${phraseId}`)
      ?.addEventListener("input", (event) => {
        confirm.disabled =
          (event.currentTarget as HTMLInputElement).value !== options.phrase;
      });
    confirm.addEventListener("click", () => {
      if (options.phrase) {
        options.onConfirmedPhrase?.(
          document.querySelector<HTMLInputElement>(`#${phraseId}`)?.value ?? "",
        );
      }
      finish(true);
    });
    activateDialog(
      `#${confirmationId}`,
      options.phrase ? `#${phraseId}` : `#${confirmationId}-cancel`,
      () => finish(false),
    );
  });
}

export async function confirmPhraseAction(
  options: ConfirmationOptions & { phrase: string },
): Promise<string | null> {
  let confirmationPhrase = "";
  const confirmed = await confirmAction({
    ...options,
    onConfirmedPhrase: (phrase) => {
      confirmationPhrase = phrase;
    },
  });
  return confirmed ? confirmationPhrase : null;
}

export function openVaultSettings() {
  $("#modal-root").innerHTML =
    `<div class="modal-backdrop" id="settings-backdrop"><section class="entry-modal vault-settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title" aria-describedby="settings-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">VAULT MANAGEMENT</p><h2 id="settings-title">Vault settings</h2></div><button class="icon-button" id="settings-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro" id="settings-description">Back up your encrypted vault, restore a previous backup, rotate its master password, or securely reset it.</p><div class="settings-actions"><button class="settings-action" id="export-backup"><span class="settings-action-icon">${icon("download", 18)}</span><span><strong>Export encrypted backup</strong><small>Create a portable encrypted copy protected by your current master password.</small></span></button><button class="settings-action" id="restore-backup"><span class="settings-action-icon">${icon("upload", 18)}</span><span><strong>Restore encrypted backup</strong><small>Validate and replace this vault with a previously exported copy.</small></span></button><button class="settings-action" id="change-password"><span class="settings-action-icon">${icon("key", 18)}</span><span><strong>Change master password</strong><small>Re-encrypt the vault with a fresh salt and a new master password.</small></span></button><button class="settings-action" id="authenticated-reset"><span class="settings-action-icon">${icon("trash", 18)}</span><span><strong>Reset this vault</strong><small>Verify your current master password and optionally save one final encrypted backup.</small></span></button></div><p class="settings-footnote">${icon("shield", 14)} Backup files contain authenticated ciphertext only.</p></section></div>`;
  $(".settings-actions").insertAdjacentHTML(
    "beforebegin",
    `<div class="settings-preferences"><label class="auto-lock-setting" for="auto-lock-timeout"><span><strong>Auto-lock timeout</strong><small>Activity resets the timer. Passman checks the deadline again after focus, resume, or workstation unlock.</small></span><select id="auto-lock-timeout">${AUTO_LOCK_OPTIONS.map((minutes) => `<option value="${minutes}" ${minutes === getAutoLockMinutes() ? "selected" : ""}>${minutes} ${minutes === 1 ? "minute" : "minutes"}</option>`).join("")}</select></label><label class="auto-lock-setting" for="password-age-limit"><span><strong>Password age limit</strong><small>Indicators turn yellow 30 days before this limit and red when the limit is reached.</small></span><span class="number-setting"><input id="password-age-limit" type="number" min="${MIN_PASSWORD_AGE_LIMIT_DAYS}" max="${MAX_PASSWORD_AGE_LIMIT_DAYS}" step="1" value="${getPasswordAgeLimitDays()}" /><span>days</span></span></label></div>`,
  );
  $("#settings-close").addEventListener("click", closeModal);
  const settingsBackdrop = $("#settings-backdrop");
  settingsBackdrop.addEventListener("click", (event) => {
    if (event.target === settingsBackdrop) closeModal();
  });
  $("#export-backup").addEventListener("click", () => void exportBackup());
  $("#restore-backup").addEventListener("click", openRestoreModal);
  $("#change-password").addEventListener("click", openChangePasswordModal);
  $("#authenticated-reset").addEventListener(
    "click",
    openAuthenticatedResetModal,
  );
  $("#auto-lock-timeout").addEventListener("change", (event) => {
    const minutes = Number((event.currentTarget as HTMLSelectElement).value);
    if (
      !AUTO_LOCK_OPTIONS.includes(minutes as (typeof AUTO_LOCK_OPTIONS)[number])
    ) {
      toast("Choose a supported auto-lock timeout.", true);
      return;
    }
    try {
      setAutoLockMinutes(minutes);
      callbacks.recordActivity();
      toast(
        `Auto-lock timeout set to ${minutes} ${minutes === 1 ? "minute" : "minutes"}.`,
      );
    } catch (error) {
      fail(error);
    }
  });
  $("#password-age-limit").addEventListener("change", async (event) => {
    const input = event.currentTarget as HTMLInputElement;
    const previous = getPasswordAgeLimitDays();
    try {
      const days = Number(input.value);
      const preferences = await vaultApi.setPreferences({
        passwordAgeLimitDays: days,
      });
      setPasswordAgeLimitDays(preferences.passwordAgeLimitDays);
      callbacks.renderEntries();
      toast(
        `Password age limit set to ${preferences.passwordAgeLimitDays} days.`,
      );
    } catch (error) {
      input.value = String(previous);
      fail(error);
    }
  });
  activateDialog(".vault-settings-modal", "#export-backup");
}

async function exportBackup() {
  try {
    const filename = await vaultApi.exportBackup();
    if (!filename) return;
    closeModal();
    toast(`Encrypted backup saved as ${filename}.`);
  } catch (error) {
    fail(error);
  }
}

function openRestoreModal() {
  $("#modal-root").innerHTML =
    `<div class="modal-backdrop" id="restore-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="restore-title" aria-describedby="restore-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">RESTORE BACKUP</p><h2 id="restore-title">Replace this vault</h2></div><button class="icon-button" id="restore-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro" id="restore-description">Enter the master password that protects the backup. Passman will then open a native file picker showing encrypted .passman backups.</p><form id="restore-form" class="entry-form"><label for="backup-password">Backup master password <span>*</span><input id="backup-password" name="password" type="password" autocomplete="current-password" minlength="12" required /></label><p class="destructive-note">The selected backup is validated before existing entries in this vault are replaced.</p><div class="modal-footer settings-form-footer"><button type="button" class="button button-quiet" id="restore-back">Back</button><button type="submit" class="button button-primary">${icon("upload", 16)} Choose backup and restore</button></div></form></section></div>`;
  $("#restore-close").addEventListener("click", closeModal);
  $("#restore-back").addEventListener("click", openVaultSettings);
  $("#restore-backdrop").addEventListener("click", (event) => {
    if (event.target === $("#restore-backdrop")) closeModal();
  });
  $("#restore-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const submit = $<HTMLButtonElement>('button[type="submit"]', form);
    try {
      if (
        !(await confirmAction({
          title: "Replace the current vault?",
          description:
            "All entries in the current vault will be replaced by the selected encrypted backup.",
          confirmLabel: "Restore and replace",
        }))
      )
        return;
      submit.disabled = true;
      const data = new FormData(form);
      const snapshot = await vaultApi.importBackup(
        String(data.get("password") ?? ""),
      );
      if (!snapshot) {
        submit.disabled = false;
        return;
      }
      applyVaultSnapshot(snapshot);
      state.searchTerm = "";
      state.activeFilter = "All items";
      closeModal();
      $<HTMLInputElement>("#search-input").value = "";
      callbacks.setFilter("All items");
      toast("Encrypted backup restored.");
    } catch (error) {
      submit.disabled = false;
      fail(error);
    }
  });
  activateDialog("#restore-backdrop [role=dialog]", "#backup-password");
}

function openAuthenticatedResetModal() {
  $("#modal-root").innerHTML =
    `<div class="modal-backdrop" id="authenticated-reset-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="authenticated-reset-title" aria-describedby="authenticated-reset-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">RESET VAULT</p><h2 id="authenticated-reset-title">Permanently reset this vault</h2></div><button class="icon-button" id="authenticated-reset-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro" id="authenticated-reset-description">Enter the current master password. Rust verifies it before deleting the encrypted vault.</p><form id="authenticated-reset-form" class="entry-form"><label for="reset-master-password">Current master password <span>*</span><input id="reset-master-password" name="currentPassword" type="password" autocomplete="current-password" minlength="12" required /></label><label class="favorite-toggle"><input name="createBackup" type="checkbox" checked /><span class="checkmark" aria-hidden="true"></span><span class="favorite-text">Create a final encrypted backup before reset</span></label><p class="destructive-note">Without a backup, every saved password will be permanently lost.</p><p class="auth-error" id="authenticated-reset-error"></p><div class="modal-footer settings-form-footer"><button type="button" class="button button-quiet" id="authenticated-reset-back">Back</button><button type="submit" class="button button-danger">${icon("trash", 16)} Verify and reset</button></div></form></section></div>`;
  $("#authenticated-reset-close").addEventListener("click", closeModal);
  $("#authenticated-reset-back").addEventListener("click", openVaultSettings);
  const backdrop = $("#authenticated-reset-backdrop");
  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop) closeModal();
  });
  $("#authenticated-reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const submit = $<HTMLButtonElement>('button[type="submit"]', form);
    const passwordInput = $<HTMLInputElement>("#reset-master-password");
    const errorElement = $("#authenticated-reset-error");
    submit.disabled = true;
    errorElement.textContent = "";
    try {
      const data = new FormData(form);
      const result = await vaultApi.authenticatedReset(
        String(data.get("currentPassword") ?? ""),
        data.get("createBackup") === "on",
      );
      if (!result.reset) {
        submit.disabled = false;
        return;
      }
      callbacks.completeVaultReset(result.backupFileName);
    } catch (error) {
      passwordInput.value = "";
      errorElement.textContent = String(error).replace(/^Error: /, "");
      submit.disabled = false;
      passwordInput.focus();
    }
  });
  activateDialog(
    "#authenticated-reset-backdrop [role=dialog]",
    "#reset-master-password",
  );
}

function openChangePasswordModal() {
  $("#modal-root").innerHTML =
    `<div class="modal-backdrop" id="password-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="password-title" aria-describedby="password-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">MASTER PASSWORD</p><h2 id="password-title">Change master password</h2></div><button class="icon-button" id="password-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro" id="password-description">Your vault will be re-encrypted with a fresh random salt. Existing backups will continue to use their original passwords.</p><form id="change-password-form" class="entry-form"><label for="current-master-password">Current master password <span>*</span><input id="current-master-password" name="currentPassword" type="password" autocomplete="current-password" minlength="12" required autofocus /></label><label for="new-master-password">New master password <span>*</span><input id="new-master-password" name="newPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label for="confirm-new-master-password">Confirm new master password <span>*</span><input id="confirm-new-master-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required /></label><p class="auth-error" id="password-error"></p><div class="modal-footer settings-form-footer"><button type="button" class="button button-quiet" id="password-back">Back</button><button type="submit" class="button button-primary">${icon("key", 16)} Change password</button></div></form></section></div>`;
  $("#password-close").addEventListener("click", closeModal);
  $("#password-back").addEventListener("click", openVaultSettings);
  $("#password-backdrop").addEventListener("click", (event) => {
    if (event.target === $("#password-backdrop")) closeModal();
  });
  $("#change-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const currentPassword = String(data.get("currentPassword") ?? "");
    const newPassword = String(data.get("newPassword") ?? "");
    const errorElement = $("#password-error");
    if (newPassword !== String(data.get("confirmPassword") ?? "")) {
      errorElement.textContent = "New master passwords do not match.";
      return;
    }
    const submit = $<HTMLButtonElement>('button[type="submit"]', form);
    submit.disabled = true;
    errorElement.textContent = "";
    try {
      await vaultApi.changeMasterPassword(currentPassword, newPassword);
      form.reset();
      closeModal();
      toast("Master password changed securely.");
    } catch (error) {
      submit.disabled = false;
      errorElement.textContent = String(error).replace(/^Error: /, "");
    }
  });
  activateDialog(
    "#password-backdrop [role=dialog]",
    "#current-master-password",
  );
}

export async function showTotp(id: string) {
  try {
    const result = await vaultApi.getTotpCode(id);
    const entry = state.entries.find((item) => item.id === id);
    $("#modal-root").innerHTML =
      `<div class="modal-backdrop" id="totp-backdrop"><section class="totp-modal" role="dialog" aria-modal="true" aria-labelledby="totp-title" aria-describedby="totp-description" tabindex="-1"><button class="icon-button totp-close" id="totp-close" aria-label="Close">${icon("close", 19)}</button><div class="totp-icon">${icon("key", 22)}</div><p class="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2 id="totp-title">${escapeHtml(entry?.title ?? "Authenticator")}</h2><p class="totp-copy" id="totp-description">Your current one-time code</p><output class="totp-code" id="totp-code">${result.code}</output><div class="totp-countdown"><span class="totp-progress" id="totp-progress" style="--progress:${(result.secondsRemaining / 30) * 100}%"></span><span id="totp-remaining">${result.secondsRemaining}s</span></div><button class="button button-primary totp-copy" id="copy-totp">${icon("copy", 16)} Copy code</button><p class="totp-footnote">Codes refresh automatically · valid for 30 seconds</p></section></div>`;
    $("#totp-close").addEventListener("click", closeModal);
    $("#totp-backdrop").addEventListener("click", (event) => {
      if (event.target === $("#totp-backdrop")) closeModal();
    });
    $("#copy-totp").addEventListener("click", () => {
      void copyText($("#totp-code").textContent ?? "");
    });
    activateDialog(".totp-modal", "#copy-totp");
    stopTotpRefresh();
    totpRefreshTimer = window.setInterval(async () => {
      if (!document.querySelector("#totp-code")) {
        stopTotpRefresh();
        return;
      }
      try {
        const next = await vaultApi.getTotpCode(id);
        const code = document.querySelector<HTMLElement>("#totp-code");
        const remaining =
          document.querySelector<HTMLElement>("#totp-remaining");
        const progress = document.querySelector<HTMLElement>("#totp-progress");
        if (!code || !remaining || !progress) {
          stopTotpRefresh();
          return;
        }
        code.textContent = next.code;
        remaining.textContent = `${next.secondsRemaining}s`;
        progress.style.setProperty(
          "--progress",
          `${(next.secondsRemaining / 30) * 100}%`,
        );
      } catch (error) {
        stopTotpRefresh();
        if (document.querySelector("#totp-code")) fail(error);
      }
    }, 1000);
  } catch (error) {
    fail(error);
  }
}

export function openEntryModal(entry?: EntryDetails) {
  const editing = Boolean(entry);
  const favorite = entry?.favorite ?? false;
  const note = entry?.notes ?? "";
  $("#modal-root").innerHTML =
    `<div class="modal-backdrop" id="modal-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="entry-description" tabindex="-1"><div class="modal-head"><div><p class="eyebrow">SECURE ITEM</p><h2 id="modal-title">${editing ? "Edit password" : "Add a password"}</h2></div><button class="icon-button" id="modal-close" aria-label="Close">${icon("close", 19)}</button></div><p class="dialog-description" id="entry-description">${editing ? "Update this encrypted vault item." : "Add a new encrypted item to your vault."} Required fields are marked with an asterisk.</p><form id="entry-form" class="entry-form"><label>Item name <span>*</span><input name="title" maxlength="200" required placeholder="e.g. Personal email" value="${escapeHtml(entry?.title ?? "")}" autofocus /></label><label>Username or email<input name="username" maxlength="500" autocomplete="off" placeholder="name@example.com" value="${escapeHtml(entry?.username ?? "")}" /></label><label>Password <span>*</span><div class="password-field"><input name="password" type="${state.passwordVisible ? "text" : "password"}" maxlength="4096" required autocomplete="new-password" placeholder="Enter or generate a password" value="${escapeHtml(entry?.password ?? state.generatedPassword)}" /><button type="button" class="inline-action" id="toggle-password" aria-label="Show password">${icon("eye", 16)}</button><button type="button" class="inline-action generate-inline" id="modal-generate">${icon("spark", 15)} Generate</button>${!editing ? `<button type="button" class="inline-action copy-generated-inline" id="copy-entry-password" aria-label="Copy generated password" title="Copy generated password">${icon("copy", 15)}</button>` : ""}</div></label><label>Website<input name="website" maxlength="2000" placeholder="https://example.com" value="${escapeHtml(entry?.website ?? "")}" /></label><label>Notes <span class="optional">OPTIONAL</span><textarea name="notes" maxlength="10000" rows="3" placeholder="Add a note…">${escapeHtml(note)}</textarea></label><label class="favorite-toggle"><input name="favorite" type="checkbox" ${favorite ? "checked" : ""} /><span class="checkmark" aria-hidden="true"></span><span class="favorite-text">Add to favorites</span></label><p class="form-message" id="entry-message" role="status" aria-live="polite"></p><div class="modal-footer"><button type="button" class="button button-quiet" id="modal-cancel">Cancel</button><button type="submit" class="button button-primary">${icon("check", 16)} ${editing ? "Save changes" : "Save password"}</button></div></form></section></div>`;
  $("#entry-form").insertAdjacentHTML(
    "beforeend",
    `<div class="totp-settings"><div class="totp-settings-head"><span class="totp-settings-icon">${icon("key", 16)}</span><span><strong>Authenticator codes</strong><small>${entry ? (entry.hasTotp ? "Set up for this item" : "Not configured") : "Save this item first to set up codes."}</small></span>${entry?.hasTotp ? '<button type="button" class="text-danger" id="remove-totp">Remove</button>' : ""}</div>${entry ? `<label for="totp-secret-input">${entry.hasTotp ? "Replace setup key" : "Setup key"}<input id="totp-secret-input" type="password" autocomplete="off" placeholder="Paste the Base32 setup key" maxlength="128" /></label><button type="button" class="button button-quiet" id="save-totp">${icon("key", 15)} ${entry.hasTotp ? "Update authenticator" : "Set up authenticator"}</button>` : ""}</div>`,
  );
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal-cancel").addEventListener("click", closeModal);
  $("#modal-backdrop").addEventListener("click", (event) => {
    if (event.target === $("#modal-backdrop")) closeModal();
  });
  $("#toggle-password").addEventListener("click", () => {
    const input = $<HTMLInputElement>("[name=password]");
    state.passwordVisible = input.type === "password";
    input.type = state.passwordVisible ? "text" : "password";
  });
  $("#modal-generate").addEventListener("click", async () => {
    await generatePassword();
    $<HTMLInputElement>("[name=password]").value = state.generatedPassword;
  });
  document
    .querySelector("#copy-entry-password")
    ?.addEventListener("click", () => {
      void copyText($<HTMLInputElement>("[name=password]").value);
    });
  document.querySelector("#save-totp")?.addEventListener("click", async () => {
    const secret = $<HTMLInputElement>("#totp-secret-input").value.trim();
    if (!entry || !secret) {
      toast("Enter the authenticator setup key.", true);
      return;
    }
    try {
      state.entries = await vaultApi.setTotpSecret(entry.id, secret);
      toast("Authenticator set up securely.");
      openEntryModal(await vaultApi.getEntry(entry.id));
    } catch (error) {
      fail(error);
    }
  });
  document
    .querySelector("#remove-totp")
    ?.addEventListener("click", async () => {
      if (
        !entry ||
        !(await confirmAction({
          title: "Remove this authenticator?",
          description: `One-time codes for ${entry.title} will no longer be available in Passman.`,
          confirmLabel: "Remove authenticator",
        }))
      )
        return;
      try {
        state.entries = await vaultApi.removeTotpSecret(entry.id);
        toast("Authenticator removed.");
        openEntryModal(await vaultApi.getEntry(entry.id));
      } catch (error) {
        fail(error);
      }
    });
  $("#entry-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const updated: EntryInput = {
      id: entry?.id ?? crypto.randomUUID(),
      title: String(data.get("title") ?? ""),
      username: String(data.get("username") ?? ""),
      password: String(data.get("password") ?? ""),
      website: String(data.get("website") ?? ""),
      notes: String(data.get("notes") ?? ""),
      favorite: data.get("favorite") === "on",
      totpSecret: null,
      updatedAt: Date.now(),
      passwordChangedAt: entry?.passwordChangedAt ?? Date.now(),
    };
    const submit = $<HTMLButtonElement>('button[type="submit"]', form);
    const message = $("#entry-message");
    submit.disabled = true;
    message.textContent = editing ? "Saving changes..." : "Saving password...";
    message.classList.remove("error");
    try {
      state.entries = await vaultApi.saveEntry(updated);
      closeModal();
      if (!editing) {
        state.searchTerm = "";
        state.activeFilter = "All items";
        $<HTMLInputElement>("#search-input").value = "";
      }
      callbacks.setFilter(editing ? state.activeFilter : "All items");
      toast(
        editing ? "Password updated securely." : "Password saved securely.",
      );
    } catch (error) {
      const errorMessage = String(error).replace(/^Error: /, "");
      submit.disabled = false;
      message.textContent = errorMessage;
      message.classList.add("error");
      toast(errorMessage, true);
    }
  });
  activateDialog("#modal-backdrop [role=dialog]", "[name=title]");
}
