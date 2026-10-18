import { invoke } from "@tauri-apps/api/core";

declare global {
  interface Window { __TAURI_INTERNALS__?: unknown }
}

interface EntrySummary {
  id: string;
  title: string;
  username: string;
  website: string;
  notes: string;
  favorite: boolean;
  hasTotp: boolean;
  updatedAt: number;
}
interface EntryDetails extends EntrySummary { password: string }
interface EntryInput {
  id: string;
  title: string;
  username: string;
  password: string;
  website: string;
  notes: string;
  favorite: boolean;
  totpSecret: null;
  updatedAt: number;
}
interface Status { exists: boolean; unlocked: boolean; entryCount: number }
interface GeneratorOptions { length: number; uppercase: boolean; lowercase: boolean; numbers: boolean; symbols: boolean }
interface TotpResult { code: string; secondsRemaining: number }

const $ = <T extends HTMLElement>(selector: string, root: ParentNode = document): T => {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`Missing UI element: ${selector}`);
  return element;
};
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);
const icon = (name: string, size = 18) => {
  const paths: Record<string, string> = {
    shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2m3 0-1 14H6L5 6m4 4v6m6-6v6"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L9 17l-4 1 1-4Z"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9A7 7 0 0 1 17.5 6.5L20 12M4 12l2.5 5.5A7 7 0 0 0 18.4 15"/>',
    key: '<circle cx="8" cy="15" r="5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z"/>',
    dots: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    close: '<path d="m18 6-12 12M6 6l12 12"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    spark: '<path d="m12 3 1.9 5.8L20 11l-6.1 2.2L12 19l-2-5.8L4 11l6-2.2L12 3Z"/><path d="m19 14 1.2 2.8L23 18l-2.8 1.2L19 22l-1.2-2.8L15 18l2.8-1.2L19 14Z"/>',
    settings: '<path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5Z"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.03 1.56V21h-4v-.08A1.7 1.7 0 0 0 8.94 19.4a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.57 15a1.7 1.7 0 0 0-1.56-1.03H3v-4h.08A1.7 1.7 0 0 0 4.6 8.94a1.7 1.7 0 0 0-.34-1.88L4.2 7l2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.57a1.7 1.7 0 0 0 1.03-1.56V3h4v.08A1.7 1.7 0 0 0 15.06 4.6a1.7 1.7 0 0 0 1.88-.34L17 4.2 19.83 7l-.06.06A1.7 1.7 0 0 0 19.43 9c.22.62.8 1.03 1.46 1.03H21v4h-.08A1.7 1.7 0 0 0 19.4 15Z"/>',
    download: '<path d="M12 3v12m0 0 4-4m-4 4-4-4"/><path d="M5 19h14"/>',
    upload: '<path d="M12 16V4m0 0 4 4m-4-4-4 4"/><path d="M5 20h14"/>',
  };
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] ?? ""}</svg>`;
};

let entries: EntrySummary[] = [];
let lockTimer = 0;
let activeFilter = "All items";
let searchTerm = "";
let generatedPassword = "";
let toastTimer = 0;
let clipboardTimer = 0;
let passwordVisible = false;
let totpRefreshTimer = 0;

function toast(message: string, error = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el.classList.remove("show"), 3000);
}

function armAutoLock() {
  window.clearTimeout(lockTimer);
  lockTimer = window.setTimeout(() => void lockVault(), 5 * 60 * 1000);
}
function fail(error: unknown) { toast(String(error).replace(/^Error: /, ""), true); }
function favicon(title: string) { return title.trim().charAt(0).toUpperCase() || "P"; }
function getHostname(url: string) {
  try { return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, ""); }
  catch { return url; }
}
function timeLabel(timestamp: number) {
  const days = Math.floor((Date.now() - timestamp) / 86_400_000);
  if (days <= 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(timestamp);
}

function authView(exists: boolean, message = "") {
  $("#app").innerHTML = `
    <main class="auth-shell">
      <section class="auth-card">
        <div class="brand-lockup"><span class="brand-icon">${icon("shield", 23)}</span><span>passman<span class="brand-period">.</span></span></div>
        <div class="auth-mark">${icon(exists ? "lock" : "shield", 24)}</div>
        <p class="eyebrow">YOUR PASSWORDS, PROTECTED</p>
        <h1>${exists ? "Welcome back." : "A safer place\nfor your passwords."}</h1>
        <p class="auth-copy">${exists ? "Unlock your vault to pick up where you left off." : "Create a vault secured by a master password only you know."}</p>
        <form id="auth-form" class="auth-form">
          ${exists ? "" : '<label for="confirm-password">Confirm master password</label><input id="confirm-password" type="password" autocomplete="new-password" placeholder="At least 12 characters" minlength="12" required />'}
          <label for="master-password">Master password</label>
          <input id="master-password" type="password" autocomplete="${exists ? "current-password" : "new-password"}" placeholder="${exists ? "Enter your master password" : "At least 12 characters"}" minlength="12" required autofocus />
          <p class="auth-error" id="auth-error">${escapeHtml(message)}</p>
          <button class="button button-primary auth-submit" type="submit">${exists ? "Unlock vault" : "Create secure vault"}<span>${icon(exists ? "lock" : "plus", 17)}</span></button>
        </form>
        <div class="auth-footnote">${icon("lock", 14)} End-to-end encrypted · stored only on this device</div>
        ${exists ? '<button class="link-button" id="reset-vault">Forgot master password?</button>' : '<p class="auth-warning">Keep your master password safe. It cannot be recovered.</p>'}
      </section>
      <div class="auth-decoration"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="decoration-core">${icon("key", 40)}</div><span class="float-chip chip-one">${icon("shield", 15)} Private by design</span><span class="float-chip chip-two">256-bit encryption</span></div>
    </main>`;
  $("#auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = ($("#master-password") as HTMLInputElement).value;
    const errorEl = $("#auth-error");
    errorEl.textContent = "";
    const submit = $(".auth-submit") as HTMLButtonElement;
    submit.disabled = true;
    try {
      if (exists) await invoke("unlock_vault", { password });
      else {
        if (password !== ($("#confirm-password") as HTMLInputElement).value) throw new Error("Master passwords do not match.");
        await invoke("create_vault", { password });
      }
      await loadDashboard();
    } catch (error) {
      errorEl.textContent = String(error).replace(/^Error: /, "");
      submit.disabled = false;
    }
  });
  document.querySelector<HTMLButtonElement>("#reset-vault")?.addEventListener("click", () => {
    if (confirm("Reset this vault? This permanently deletes all saved entries. This action cannot be undone.")) void resetVault();
  });
}

async function resetVault() {
  try {
    await invoke("reset_vault");
    authView(false);
    toast("Vault reset. Create a new master password.");
  } catch (error) { fail(error); }
}

function closeModal() {
  window.clearInterval(totpRefreshTimer);
  document.querySelector<HTMLElement>("#modal-root")?.replaceChildren();
  passwordVisible = false;
}

function openVaultSettings() {
  $("#modal-root").innerHTML = `<div class="modal-backdrop" id="settings-backdrop"><section class="entry-modal vault-settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title"><div class="modal-head"><div><p class="eyebrow">VAULT MANAGEMENT</p><h2 id="settings-title">Vault settings</h2></div><button class="icon-button" id="settings-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro">Back up your encrypted vault, restore a previous backup, or rotate its master password.</p><div class="settings-actions"><button class="settings-action" id="export-backup"><span class="settings-action-icon">${icon("download", 18)}</span><span><strong>Export encrypted backup</strong><small>Create a portable encrypted copy protected by your current master password.</small></span></button><button class="settings-action" id="restore-backup"><span class="settings-action-icon">${icon("upload", 18)}</span><span><strong>Restore encrypted backup</strong><small>Validate and replace this vault with a previously exported copy.</small></span></button><button class="settings-action" id="change-password"><span class="settings-action-icon">${icon("key", 18)}</span><span><strong>Change master password</strong><small>Re-encrypt the vault with a fresh salt and a new master password.</small></span></button></div><p class="settings-footnote">${icon("shield", 14)} Backup files contain authenticated ciphertext only.</p></section></div>`;
  $("#settings-close").addEventListener("click", closeModal);
  $("#settings-backdrop").addEventListener("click", (event) => { if (event.target === $("#settings-backdrop")) closeModal(); });
  $("#export-backup").addEventListener("click", () => void exportBackup());
  $("#restore-backup").addEventListener("click", openRestoreModal);
  $("#change-password").addEventListener("click", openChangePasswordModal);
  $("#export-backup").focus();
}

async function exportBackup() {
  try {
    const filename = await invoke<string>("export_backup");
    closeModal();
    toast(`Encrypted backup saved to Downloads as ${filename}.`);
  } catch (error) { fail(error); }
}

function openRestoreModal() {
  $("#modal-root").innerHTML = `<div class="modal-backdrop" id="restore-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="restore-title"><div class="modal-head"><div><p class="eyebrow">RESTORE BACKUP</p><h2 id="restore-title">Replace this vault</h2></div><button class="icon-button" id="restore-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro">Choose an encrypted Passman backup and enter the master password that protects it. The backup is validated before your current vault is replaced.</p><form id="restore-form" class="entry-form"><label for="backup-file">Encrypted backup <span>*</span><input id="backup-file" name="backupFile" type="file" accept=".passman,application/json" required /></label><label for="backup-password">Backup master password <span>*</span><input id="backup-password" name="password" type="password" autocomplete="current-password" minlength="12" required /></label><p class="destructive-note">Existing entries in this vault will be replaced.</p><div class="modal-footer settings-form-footer"><button type="button" class="button button-quiet" id="restore-back">Back</button><button type="submit" class="button button-primary">${icon("upload", 16)} Restore backup</button></div></form></section></div>`;
  const back = () => openVaultSettings();
  $("#restore-close").addEventListener("click", closeModal);
  $("#restore-back").addEventListener("click", back);
  $("#restore-backdrop").addEventListener("click", (event) => { if (event.target === $("#restore-backdrop")) closeModal(); });
  $("#restore-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    try {
      if (!confirm("Restore this backup? Your current vault entries will be replaced.")) return;
      submit.disabled = true;
      const data = new FormData(form);
      const file = data.get("backupFile");
      if (!(file instanceof File) || file.size === 0) throw new Error("Choose a valid encrypted backup.");
      if (file.size > 64 * 1024 * 1024) throw new Error("Backup file is larger than the supported limit.");
      const backup = await file.text();
      const password = String(data.get("password") ?? "");
      entries = await invoke<EntrySummary[]>("import_backup", { backup, password });
      searchTerm = "";
      activeFilter = "All items";
      closeModal();
      ($("#search-input") as HTMLInputElement).value = "";
      setFilter("All items");
      toast("Encrypted backup restored.");
    } catch (error) {
      submit.disabled = false;
      fail(error);
    }
  });
  $("#backup-file").focus();
}

function openChangePasswordModal() {
  $("#modal-root").innerHTML = `<div class="modal-backdrop" id="password-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="password-title"><div class="modal-head"><div><p class="eyebrow">MASTER PASSWORD</p><h2 id="password-title">Change master password</h2></div><button class="icon-button" id="password-close" aria-label="Close">${icon("close", 19)}</button></div><p class="settings-intro">Your vault will be re-encrypted with a fresh random salt. Existing backups will continue to use their original passwords.</p><form id="change-password-form" class="entry-form"><label for="current-master-password">Current master password <span>*</span><input id="current-master-password" name="currentPassword" type="password" autocomplete="current-password" minlength="12" required autofocus /></label><label for="new-master-password">New master password <span>*</span><input id="new-master-password" name="newPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label for="confirm-new-master-password">Confirm new master password <span>*</span><input id="confirm-new-master-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required /></label><p class="auth-error" id="password-error"></p><div class="modal-footer settings-form-footer"><button type="button" class="button button-quiet" id="password-back">Back</button><button type="submit" class="button button-primary">${icon("key", 16)} Change password</button></div></form></section></div>`;
  $("#password-close").addEventListener("click", closeModal);
  $("#password-back").addEventListener("click", openVaultSettings);
  $("#password-backdrop").addEventListener("click", (event) => { if (event.target === $("#password-backdrop")) closeModal(); });
  $("#change-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const currentPassword = String(data.get("currentPassword") ?? "");
    const newPassword = String(data.get("newPassword") ?? "");
    const errorEl = $("#password-error");
    if (newPassword !== String(data.get("confirmPassword") ?? "")) {
      errorEl.textContent = "New master passwords do not match.";
      return;
    }
    const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    submit.disabled = true;
    errorEl.textContent = "";
    try {
      await invoke("change_master_password", { currentPassword, newPassword });
      form.reset();
      closeModal();
      toast("Master password changed securely.");
    } catch (error) {
      submit.disabled = false;
      errorEl.textContent = String(error).replace(/^Error: /, "");
    }
  });
  $("#current-master-password").focus();
}

function dashboardShell() {
  $("#app").innerHTML = `
    <div class="app-shell">
      <aside class="sidebar">
        <a class="brand-lockup" href="#" aria-label="Passman home"><span class="brand-icon">${icon("shield", 21)}</span><span>passman<span class="brand-period">.</span></span></a>
        <div class="vault-chip"><span class="vault-pulse"></span> PERSONAL VAULT <span class="vault-lock">${icon("lock", 13)}</span></div>
        <p class="nav-label">WORKSPACE</p>
        <nav class="main-nav" aria-label="Main navigation">
          <button class="nav-item active" data-filter="All items">${icon("dots", 18)}<span>All items</span><span class="nav-count" id="total-count">0</span></button>
          <button class="nav-item" data-filter="Favorites">${icon("spark", 17)}<span>Favorites</span></button>
        </nav>
        <div class="sidebar-rule"></div>
        <div class="sidebar-hint"><div class="hint-icon">${icon("shield", 17)}</div><strong>Private by design</strong><p>Your vault is encrypted on this device. Only you hold the key.</p></div>
        <div class="sidebar-bottom"><span class="avatar">${icon("lock", 15)}</span><div class="user-label"><strong>Personal vault</strong><span>Protected locally</span></div><button class="icon-button vault-settings-button" id="vault-settings" aria-label="Vault settings" title="Vault settings">${icon("settings", 17)}</button><button class="icon-button" id="lock-button" aria-label="Lock vault" title="Lock vault">${icon("lock", 17)}</button></div>
      </aside>
      <main class="main-content">
        <header class="topbar"><div class="breadcrumb">Vault <span>/</span> <strong id="breadcrumb-current">All items</strong></div><div class="top-actions"><span class="secure-status"><span class="status-dot"></span> Vault secured</span><button class="button button-primary add-button" id="add-entry">${icon("plus", 16)}<span>New item</span></button></div></header>
        <div class="content-inner">
          <section class="welcome-row"><div><p class="eyebrow">YOUR PRIVATE SPACE</p><h1 id="page-title">All items <span class="title-count" id="heading-count">0</span></h1><p class="page-subtitle">Everything you need, securely in one place.</p></div><div class="header-decoration">${icon("shield", 26)}<span>Encrypted<br/>at rest</span></div></section>
          <section class="generator-card">
            <div class="generator-top"><div class="generator-title"><span class="generator-icon">${icon("spark", 19)}</span><div><h2>Password generator</h2><p>Make a strong, unique password in a click.</p></div></div><span class="generator-badge">${icon("shield", 13)} SECURE GENERATOR</span></div>
            <div class="generated-row"><code id="generated-output" class="generated-output" aria-live="polite">Generate a strong password</code><div class="generated-actions"><button class="icon-button" id="refresh-password" aria-label="Generate password" title="Generate password">${icon("refresh", 17)}</button><button class="icon-button" id="copy-generated" aria-label="Copy password" title="Copy password">${icon("copy", 17)}</button></div></div>
            <div class="generator-controls"><div class="length-control"><label for="password-length">LENGTH <strong id="length-value">20</strong></label><input id="password-length" type="range" min="8" max="64" value="20" /></div><div class="checks"><label class="check-label"><input type="checkbox" id="opt-uppercase" checked /><span class="checkmark"></span> ABC</label><label class="check-label"><input type="checkbox" id="opt-lowercase" checked /><span class="checkmark"></span> abc</label><label class="check-label"><input type="checkbox" id="opt-numbers" checked /><span class="checkmark"></span> 123</label><label class="check-label"><input type="checkbox" id="opt-symbols" checked /><span class="checkmark"></span> #$&</label></div><button class="button generate-button" id="generate-button">${icon("spark", 15)} Generate</button></div>
          </section>
          <section class="vault-section"><div class="vault-section-head"><div><h2>Your passwords <span class="section-count" id="section-count">0</span></h2><p>Only you can see what’s inside.</p></div><div class="search-wrap">${icon("search", 16)}<input type="search" id="search-input" placeholder="Search passwords..." autocomplete="off" /><kbd>⌘ K</kbd></div></div><div id="entries-area"></div></section>
        </div>
        <footer class="main-footer"><span>${icon("lock", 13)} Your data stays yours. Always.</span><span>Encrypted locally on this device</span></footer>
      </main>
    </div><div id="modal-root"></div>`;
  $("#add-entry").addEventListener("click", () => openEntryModal());
  $("#generate-button").addEventListener("click", () => void generate());
  $("#refresh-password").addEventListener("click", () => void generate());
  $("#copy-generated").addEventListener("click", () => void copyText(generatedPassword));
  $("#password-length").addEventListener("input", (event) => { $("#length-value").textContent = (event.target as HTMLInputElement).value; });
  $("#search-input").addEventListener("input", (event) => { searchTerm = (event.target as HTMLInputElement).value.toLowerCase(); renderEntries(); });
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => button.addEventListener("click", () => setFilter(button.dataset.filter ?? "All items")));
  $("#vault-settings").addEventListener("click", openVaultSettings);
  $("#lock-button").addEventListener("click", () => void lockVault());
  document.addEventListener("keydown", keyboardShortcuts);
  ["pointerdown", "touchstart"].forEach((name) => document.addEventListener(name, armAutoLock, { passive: true }));
  document.addEventListener("keydown", armAutoLock);
  armAutoLock();
}

async function generate() {
  const options: GeneratorOptions = {
    length: Number(($("#password-length") as HTMLInputElement).value),
    uppercase: ($("#opt-uppercase") as HTMLInputElement).checked,
    lowercase: ($("#opt-lowercase") as HTMLInputElement).checked,
    numbers: ($("#opt-numbers") as HTMLInputElement).checked,
    symbols: ($("#opt-symbols") as HTMLInputElement).checked,
  };
  try {
    generatedPassword = await invoke<string>("generate_password", { options });
    $("#generated-output").textContent = generatedPassword;
    $("#generated-output").classList.add("has-password");
  } catch (error) { fail(error); }
}

async function loadDashboard() {
  entries = await invoke<EntrySummary[]>("list_entries");
  dashboardShell();
  setFilter("All items");
  await generate();
}

function setFilter(filter: string) {
  activeFilter = filter;
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.filter === filter));
  const title = filter === "Favorites" ? "Favorites" : "All items";
  $("#breadcrumb-current").textContent = title;
  $("#page-title").childNodes[0]!.textContent = `${title} `;
  renderEntries();
}

function renderEntries() {
  const filtered = entries.filter((entry) => {
    const matchesSearch = `${entry.title} ${entry.username} ${entry.website}`.toLowerCase().includes(searchTerm);
    return matchesSearch && (activeFilter !== "Favorites" || entry.favorite);
  });
  $("#total-count").textContent = String(entries.length);
  $("#heading-count").textContent = String(filtered.length);
  $("#section-count").textContent = String(filtered.length);
  const area = $("#entries-area");
  if (filtered.length === 0) {
    const searching = searchTerm.length > 0;
    area.innerHTML = `<div class="empty-state"><div class="empty-illustration">${icon(searching ? "search" : "key", 26)}</div><h3>${searching ? "No matching passwords" : activeFilter === "Favorites" ? "No favorites yet" : "Your vault is ready."}</h3><p>${searching ? "Try searching with a different name or username." : activeFilter === "Favorites" ? "Mark an item as a favorite to see it here." : "Save a login or generate a new password to get started."}</p>${!searching && activeFilter === "All items" ? `<button class="button button-primary" id="empty-add">${icon("plus", 15)} Add your first item</button>` : ""}</div>`;
    area.querySelector<HTMLButtonElement>("#empty-add")?.addEventListener("click", () => openEntryModal());
    return;
  }
  area.innerHTML = `<div class="entry-list">${filtered.sort((a, b) => b.updatedAt - a.updatedAt).map((entry) => {
    const id = escapeHtml(entry.id);
    return `<article class="entry-card" data-entry-id="${id}"><div class="entry-monogram">${escapeHtml(favicon(entry.title))}</div><div class="entry-info"><div class="entry-title-row"><h3>${escapeHtml(entry.title)}</h3>${entry.favorite ? '<span class="favorite-star">★</span>' : ""}</div><p>${escapeHtml(entry.username || "No username")}</p></div><div class="entry-site">${entry.website ? `${icon("globe", 14)}<span>${escapeHtml(getHostname(entry.website))}</span>` : `<span class="site-empty">No website</span>`}</div><div class="entry-updated">${timeLabel(entry.updatedAt)}</div><div class="entry-row-actions">${entry.hasTotp ? `<button class="icon-button entry-totp" data-id="${id}" aria-label="Show authenticator code" title="Authenticator code">${icon("key", 16)}</button>` : ""}<button class="icon-button entry-copy" data-id="${id}" aria-label="Copy password">${icon("copy", 16)}</button><button class="icon-button entry-edit" data-id="${id}" aria-label="Edit item">${icon("edit", 16)}</button><button class="icon-button entry-delete" data-id="${id}" aria-label="Delete item">${icon("trash", 16)}</button></div><div class="entry-password">${entry.hasTotp ? "Authenticator enabled" : "Password protected"}</div></article>`;
  }).join("")}</div>`;
  area.querySelectorAll<HTMLButtonElement>(".entry-copy").forEach((button) => button.addEventListener("click", async () => {
    if (!button.dataset.id) return;
    try { await copyText(await invoke<string>("get_entry_password", { id: button.dataset.id })); }
    catch (error) { fail(error); }
  }));
  area.querySelectorAll<HTMLButtonElement>(".entry-totp").forEach((button) => button.addEventListener("click", () => {
    if (button.dataset.id) void showTotp(button.dataset.id);
  }));
  area.querySelectorAll<HTMLButtonElement>(".entry-edit").forEach((button) => button.addEventListener("click", async () => {
    if (!button.dataset.id) return;
    try { openEntryModal(await invoke<EntryDetails>("get_entry", { id: button.dataset.id })); }
    catch (error) { fail(error); }
  }));
  area.querySelectorAll<HTMLButtonElement>(".entry-delete").forEach((button) => button.addEventListener("click", () => {
    const entry = entries.find((item) => item.id === button.dataset.id);
    if (entry && confirm(`Delete “${entry.title}” from your vault?`)) void deleteEntry(entry.id);
  }));
}

async function showTotp(id: string) {
  try {
    const result = await invoke<TotpResult>("get_totp_code", { id });
    const entry = entries.find((item) => item.id === id);
    $("#modal-root").innerHTML = `<div class="modal-backdrop" id="totp-backdrop"><section class="totp-modal" role="dialog" aria-modal="true" aria-labelledby="totp-title"><button class="icon-button totp-close" id="totp-close" aria-label="Close">${icon("close", 19)}</button><div class="totp-icon">${icon("key", 22)}</div><p class="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2 id="totp-title">${escapeHtml(entry?.title ?? "Authenticator")}</h2><p class="totp-copy">Your current one-time code</p><output class="totp-code" id="totp-code">${result.code}</output><div class="totp-countdown"><span class="totp-progress" id="totp-progress" style="--progress:${(result.secondsRemaining / 30) * 100}%"></span><span id="totp-remaining">${result.secondsRemaining}s</span></div><button class="button button-primary totp-copy" id="copy-totp">${icon("copy", 16)} Copy code</button><p class="totp-footnote">Codes refresh automatically · valid for 30 seconds</p></section></div>`;
    const close = closeModal;
    $("#totp-close").addEventListener("click", close);
    $("#totp-backdrop").addEventListener("click", (event) => { if (event.target === $("#totp-backdrop")) close(); });
    $("#copy-totp").addEventListener("click", () => {
      const code = $("#totp-code").textContent ?? "";
      void navigator.clipboard.writeText(code).then(() => toast("Authenticator code copied."), () => toast("Clipboard access is unavailable.", true));
    });
    window.clearInterval(totpRefreshTimer);
    totpRefreshTimer = window.setInterval(async () => {
      if (!$("#totp-code", document).isConnected) { window.clearInterval(totpRefreshTimer); return; }
      try {
        const next = await invoke<TotpResult>("get_totp_code", { id });
        $("#totp-code").textContent = next.code;
        $("#totp-remaining").textContent = `${next.secondsRemaining}s`;
        $("#totp-progress").style.setProperty("--progress", `${(next.secondsRemaining / 30) * 100}%`);
      } catch (error) { window.clearInterval(totpRefreshTimer); fail(error); }
    }, 1000);
  } catch (error) { fail(error); }
}

function openEntryModal(entry?: EntryDetails) {
  const editing = Boolean(entry);
  const favorite = entry?.favorite ?? false;
  const note = entry?.notes ?? "";
    $("#modal-root").innerHTML = `<div class="modal-backdrop" id="modal-backdrop"><section class="entry-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-head"><div><p class="eyebrow">SECURE ITEM</p><h2 id="modal-title">${editing ? "Edit password" : "Add a password"}</h2></div><button class="icon-button" id="modal-close" aria-label="Close">${icon("close", 19)}</button></div><form id="entry-form" class="entry-form"><label>Item name <span>*</span><input name="title" maxlength="200" required placeholder="e.g. Personal email" value="${escapeHtml(entry?.title ?? "")}" autofocus /></label><label>Username or email<input name="username" maxlength="500" autocomplete="off" placeholder="name@example.com" value="${escapeHtml(entry?.username ?? "")}" /></label><label>Password <span>*</span><div class="password-field"><input name="password" type="${passwordVisible ? "text" : "password"}" maxlength="4096" required autocomplete="new-password" placeholder="Enter or generate a password" value="${escapeHtml(entry?.password ?? generatedPassword)}" /><button type="button" class="inline-action" id="toggle-password" aria-label="Show password">${icon("eye", 16)}</button><button type="button" class="inline-action generate-inline" id="modal-generate">${icon("spark", 15)} Generate</button>${!editing ? `<button type="button" class="inline-action copy-generated-inline" id="copy-entry-password" aria-label="Copy generated password" title="Copy generated password">${icon("copy", 15)}</button>` : ""}</div></label><label>Website<input name="website" maxlength="2000" placeholder="https://example.com" value="${escapeHtml(entry?.website ?? "")}" /></label><label>Notes <span class="optional">OPTIONAL</span><textarea name="notes" maxlength="10000" rows="3" placeholder="Add a note…">${escapeHtml(note)}</textarea></label><label class="favorite-toggle"><input name="favorite" type="checkbox" ${favorite ? "checked" : ""} /><span class="checkmark"></span> Add to favorites</label><p class="form-message" id="entry-message" role="status" aria-live="polite"></p><div class="modal-footer"><button type="button" class="button button-quiet" id="modal-cancel">Cancel</button><button type="submit" class="button button-primary">${icon("check", 16)} ${editing ? "Save changes" : "Save password"}</button></div></form></section></div>`;
  $("#entry-form").insertAdjacentHTML("beforeend", `<div class="totp-settings"><div class="totp-settings-head"><span class="totp-settings-icon">${icon("key", 16)}</span><span><strong>Authenticator codes</strong><small>${entry ? (entry.hasTotp ? "Set up for this item" : "Not configured") : "Save this item first to set up codes."}</small></span>${entry?.hasTotp ? '<button type="button" class="text-danger" id="remove-totp">Remove</button>' : ""}</div>${entry ? `<label for="totp-secret-input">${entry.hasTotp ? "Replace setup key" : "Setup key"}<input id="totp-secret-input" type="password" autocomplete="off" placeholder="Paste the Base32 setup key" maxlength="128" /></label><button type="button" class="button button-quiet" id="save-totp">${icon("key", 15)} ${entry.hasTotp ? "Update authenticator" : "Set up authenticator"}</button>` : ""}</div>`);
  const close = closeModal;
  $("#modal-close").addEventListener("click", close);
  $("#modal-cancel").addEventListener("click", close);
  $("#modal-backdrop").addEventListener("click", (event) => { if (event.target === $("#modal-backdrop")) close(); });
  $("#toggle-password").addEventListener("click", () => {
    const input = $("[name=password]") as HTMLInputElement;
    passwordVisible = input.type === "password";
    input.type = passwordVisible ? "text" : "password";
  });
  $("#modal-generate").addEventListener("click", async () => {
    await generate();
    ($("[name=password]") as HTMLInputElement).value = generatedPassword;
  });
  $("#copy-entry-password")?.addEventListener("click", () => {
    void copyText(($("[name=password]") as HTMLInputElement).value);
  });
  $("#save-totp")?.addEventListener("click", async () => {
    const secret = ($("#totp-secret-input") as HTMLInputElement).value.trim();
    if (!entry || !secret) { toast("Enter the authenticator setup key.", true); return; }
    try {
      entries = await invoke<EntrySummary[]>("set_totp_secret", { id: entry.id, secret });
      toast("Authenticator set up securely.");
      openEntryModal(await invoke<EntryDetails>("get_entry", { id: entry.id }));
    } catch (error) { fail(error); }
  });
  $("#remove-totp")?.addEventListener("click", async () => {
    if (!entry || !confirm("Remove the authenticator setup from this item?")) return;
    try {
      entries = await invoke<EntrySummary[]>("remove_totp_secret", { id: entry.id });
      toast("Authenticator removed.");
      openEntryModal(await invoke<EntryDetails>("get_entry", { id: entry.id }));
    } catch (error) { fail(error); }
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
    };
    const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    const message = $("#entry-message");
    submit.disabled = true;
    message.textContent = editing ? "Saving changes..." : "Saving password...";
    message.classList.remove("error");
    try {
      entries = await invoke<EntrySummary[]>("save_entry", { entry: updated });
      close();
      if (!editing) {
        searchTerm = "";
        activeFilter = "All items";
        if ($("#search-input")) ($("#search-input") as HTMLInputElement).value = "";
      }
      setFilter(editing ? activeFilter : "All items");
      toast(editing ? "Password updated securely." : "Password saved securely.");
    } catch (error) {
      const errorMessage = String(error).replace(/^Error: /, "");
      submit.disabled = false;
      message.textContent = errorMessage;
      message.classList.add("error");
      toast(errorMessage, true);
    }
  });
  ($("[name=title]") as HTMLInputElement).focus();
}

async function deleteEntry(id: string) {
  try {
    entries = await invoke<EntrySummary[]>("delete_entry", { id });
    renderEntries();
    toast("Password removed from your vault.");
  } catch (error) { fail(error); }
}

async function copyText(value: string) {
  if (!value) { toast("Generate a password first.", true); return; }
  try {
    await navigator.clipboard.writeText(value);
    window.clearTimeout(clipboardTimer);
    clipboardTimer = window.setTimeout(async () => {
      try {
        if (await navigator.clipboard.readText() === value) await navigator.clipboard.writeText("");
      } catch { /* Clipboard read permission is optional; never log clipboard contents. */ }
    }, 30_000);
    toast("Copied. Clipboard clears in 30 seconds.");
  } catch { toast("Clipboard access is unavailable.", true); }
}

async function lockVault() {
  try {
    window.clearTimeout(lockTimer);
    document.removeEventListener("pointerdown", armAutoLock);
    document.removeEventListener("keydown", armAutoLock);
    document.removeEventListener("touchstart", armAutoLock);
    closeModal();
    await invoke("lock_vault");
    entries = [];
    generatedPassword = "";
    searchTerm = "";
    document.removeEventListener("keydown", keyboardShortcuts);
    const status = await invoke<Status>("vault_status");
    authView(status.exists);
  } catch (error) { fail(error); }
}

function keyboardShortcuts(event: KeyboardEvent) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("#search-input")?.focus();
  }
  if (event.key === "Escape") closeModal();
}

async function boot() {
  if (!("__TAURI_INTERNALS__" in window)) {
    $("#app").innerHTML = `<main class="auth-shell"><section class="auth-card"><div class="brand-lockup"><span class="brand-icon">${icon("shield", 23)}</span>passman<span class="brand-period">.</span></div><h1>Open Passman as a desktop app</h1><p class="auth-copy">The development web page does not have access to the secure Rust vault. Launch Passman with <strong>npm run tauri dev</strong>.</p></section></main>`;
    return;
  }
  try {
    const status = await invoke<Status>("vault_status");
    if (status.unlocked) await loadDashboard();
    else authView(status.exists);
  } catch (error) {
    $("#app").innerHTML = `<main class="auth-shell"><section class="auth-card"><div class="brand-lockup"><span class="brand-icon">${icon("shield", 23)}</span>passman<span class="brand-period">.</span></div><h1>Unable to open Passman</h1><p class="auth-copy">${escapeHtml(String(error))}</p><p class="auth-warning">When developing on Linux, install WebKitGTK and the Tauri system prerequisites, then relaunch.</p></section></main>`;
  }
}

void boot();
