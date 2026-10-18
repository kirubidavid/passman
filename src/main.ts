import { generatePassword } from "./generator";
import { closeModal, configureModal } from "./modal";
import {
  authView,
  configureRendering,
  dashboardShell,
  renderEntries,
  setFilter,
} from "./rendering";
import {
  applyVaultSnapshot,
  clearUnlockedState,
  createAutoLock,
} from "./state";
import { $, escapeHtml, fail, icon, toast } from "./ui";
import { vaultApi } from "./vault-api";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

let lockInProgress = false;
const autoLock = createAutoLock(() => void lockVault());

async function resetVault() {
  try {
    await vaultApi.reset();
    authView(false);
    toast("Vault reset. Create a new master password.");
  } catch (error) {
    fail(error);
  }
}

async function loadDashboard() {
  applyVaultSnapshot(await vaultApi.listEntries());
  dashboardShell();
  setFilter("All items");
  await generatePassword();
}

async function lockVault() {
  if (lockInProgress) return;
  lockInProgress = true;
  try {
    autoLock.stop();
    await vaultApi.lock();
    clearUnlockedState();
    closeModal();
    document.removeEventListener("keydown", keyboardShortcuts);
    authView((await vaultApi.status()).exists);
  } catch (error) {
    fail(error);
    autoLock.start();
  } finally {
    lockInProgress = false;
  }
}

function keyboardShortcuts(event: KeyboardEvent) {
  if (document.querySelector('[role="dialog"]')) return;
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    document.querySelector<HTMLElement>("#search-input")?.focus();
  }
}

configureModal({
  setFilter,
  renderEntries,
  recordActivity: autoLock.recordActivity,
});

configureRendering({
  loadDashboard,
  resetVault,
  lockVault,
  startAutoLock() {
    document.removeEventListener("keydown", keyboardShortcuts);
    document.addEventListener("keydown", keyboardShortcuts);
    autoLock.start();
  },
});

async function boot() {
  if (!("__TAURI_INTERNALS__" in window)) {
    $("#app").innerHTML =
      `<main class="auth-shell"><section class="auth-card"><div class="brand-lockup"><span class="brand-icon">${icon("shield", 23)}</span>passman<span class="brand-period">.</span></div><h1>Open Passman as a desktop app</h1><p class="auth-copy">The development web page does not have access to the secure Rust vault. Launch Passman with <strong>npm run tauri dev</strong>.</p></section></main>`;
    return;
  }
  try {
    const status = await vaultApi.status();
    if (status.unlocked) await loadDashboard();
    else authView(status.exists);
  } catch (error) {
    $("#app").innerHTML =
      `<main class="auth-shell"><section class="auth-card"><div class="brand-lockup"><span class="brand-icon">${icon("shield", 23)}</span>passman<span class="brand-period">.</span></div><h1>Unable to open Passman</h1><p class="auth-copy">${escapeHtml(String(error))}</p><p class="auth-warning">When developing on Linux, install WebKitGTK and the Tauri system prerequisites, then relaunch.</p></section></main>`;
  }
}

void boot();
