import { copyText } from "./clipboard";
import { generatePassword } from "./generator";
import { openEntryModal, openVaultSettings, showTotp } from "./modal";
import { state } from "./state";
import { $, escapeHtml, fail, icon, toast } from "./ui";
import { vaultApi } from "./vault-api";

interface RenderingCallbacks {
  loadDashboard(): Promise<void>;
  resetVault(): Promise<void>;
  lockVault(): Promise<void>;
  startAutoLock(): void;
}

let callbacks: RenderingCallbacks;

export function configureRendering(next: RenderingCallbacks) {
  callbacks = next;
}

function favicon(title: string) {
  return title.trim().charAt(0).toUpperCase() || "P";
}

function getHostname(url: string) {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(
      /^www\./,
      "",
    );
  } catch {
    return url;
  }
}

function timeLabel(timestamp: number) {
  const days = Math.floor((Date.now() - timestamp) / 86_400_000);
  if (days <= 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
  }).format(timestamp);
}

export function authView(exists: boolean, message = "") {
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
    const password = $<HTMLInputElement>("#master-password").value;
    const errorElement = $("#auth-error");
    errorElement.textContent = "";
    const submit = $<HTMLButtonElement>(".auth-submit");
    submit.disabled = true;
    try {
      if (exists) await vaultApi.unlock(password);
      else {
        if (password !== $<HTMLInputElement>("#confirm-password").value) {
          throw new Error("Master passwords do not match.");
        }
        await vaultApi.create(password);
      }
      await callbacks.loadDashboard();
    } catch (error) {
      errorElement.textContent = String(error).replace(/^Error: /, "");
      submit.disabled = false;
    }
  });
  document.querySelector<HTMLButtonElement>("#reset-vault")?.addEventListener("click", () => {
    if (
      confirm(
        "Reset this vault? This permanently deletes all saved entries. This action cannot be undone.",
      )
    ) {
      void callbacks.resetVault();
    }
  });
}

export function dashboardShell() {
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
            <div class="generator-controls"><div class="length-control"><label for="password-length">LENGTH <strong id="length-value">20</strong></label><input id="password-length" type="range" min="8" max="64" value="20" /></div><div class="checks" role="group" aria-label="Character types"><label class="check-label"><input type="checkbox" id="opt-uppercase" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Uppercase <span aria-hidden="true">ABC</span></span></label><label class="check-label"><input type="checkbox" id="opt-lowercase" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Lowercase <span aria-hidden="true">abc</span></span></label><label class="check-label"><input type="checkbox" id="opt-numbers" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Numbers <span aria-hidden="true">123</span></span></label><label class="check-label"><input type="checkbox" id="opt-symbols" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Symbols <span aria-hidden="true">#$&</span></span></label></div><button class="button generate-button" id="generate-button">${icon("spark", 15)} Generate</button></div>
          </section>
          <section class="vault-section"><div class="vault-section-head"><div><h2>Your passwords <span class="section-count" id="section-count">0</span></h2><p>Only you can see what’s inside.</p></div><div class="search-wrap">${icon("search", 16)}<input type="search" id="search-input" placeholder="Search passwords..." autocomplete="off" /><kbd>⌘ K</kbd></div></div><div id="entries-area"></div></section>
        </div>
        <footer class="main-footer"><span>${icon("lock", 13)} Your data stays yours. Always.</span><span>Encrypted locally on this device</span></footer>
      </main>
    </div><div id="modal-root"></div>`;
  $("#add-entry").addEventListener("click", () => openEntryModal());
  $("#generate-button").addEventListener("click", () => void generatePassword());
  $("#refresh-password").addEventListener("click", () => void generatePassword());
  $("#copy-generated").addEventListener("click", () => void copyText(state.generatedPassword));
  $("#password-length").addEventListener("input", (event) => {
    $("#length-value").textContent = (event.target as HTMLInputElement).value;
  });
  $("#search-input").addEventListener("input", (event) => {
    state.searchTerm = (event.target as HTMLInputElement).value.toLowerCase();
    renderEntries();
  });
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setFilter(button.dataset.filter ?? "All items"));
  });
  $("#vault-settings").addEventListener("click", openVaultSettings);
  $("#lock-button").addEventListener("click", () => void callbacks.lockVault());
  callbacks.startAutoLock();
}

export function setFilter(filter: string) {
  state.activeFilter = filter;
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === filter);
  });
  const title = filter === "Favorites" ? "Favorites" : "All items";
  $("#breadcrumb-current").textContent = title;
  const titleText = $("#page-title").firstChild;
  if (!titleText) throw new Error("Missing page title text");
  titleText.textContent = `${title} `;
  renderEntries();
}

export function renderEntries() {
  const filtered = state.entries.filter((entry) => {
    const matchesSearch = `${entry.title} ${entry.username} ${entry.website}`
      .toLowerCase()
      .includes(state.searchTerm);
    return matchesSearch && (state.activeFilter !== "Favorites" || entry.favorite);
  });
  $("#total-count").textContent = String(state.entries.length);
  $("#heading-count").textContent = String(filtered.length);
  $("#section-count").textContent = String(filtered.length);
  const area = $("#entries-area");
  if (filtered.length === 0) {
    const searching = state.searchTerm.length > 0;
    area.innerHTML = `<div class="empty-state"><div class="empty-illustration">${icon(searching ? "search" : "key", 26)}</div><h3>${searching ? "No matching passwords" : state.activeFilter === "Favorites" ? "No favorites yet" : "Your vault is ready."}</h3><p>${searching ? "Try searching with a different name or username." : state.activeFilter === "Favorites" ? "Mark an item as a favorite to see it here." : "Save a login or generate a new password to get started."}</p>${!searching && state.activeFilter === "All items" ? `<button class="button button-primary" id="empty-add">${icon("plus", 15)} Add your first item</button>` : ""}</div>`;
    area.querySelector<HTMLButtonElement>("#empty-add")?.addEventListener("click", () => {
      openEntryModal();
    });
    return;
  }
  area.innerHTML = `<div class="entry-list">${filtered
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map((entry) => {
      const id = escapeHtml(entry.id);
      return `<article class="entry-card" data-entry-id="${id}"><div class="entry-monogram">${escapeHtml(favicon(entry.title))}</div><div class="entry-info"><div class="entry-title-row"><h3>${escapeHtml(entry.title)}</h3>${entry.favorite ? '<span class="favorite-star">★</span>' : ""}</div><p>${escapeHtml(entry.username || "No username")}</p></div><div class="entry-site">${entry.website ? `${icon("globe", 14)}<span>${escapeHtml(getHostname(entry.website))}</span>` : '<span class="site-empty">No website</span>'}</div><div class="entry-updated">${timeLabel(entry.updatedAt)}</div><div class="entry-row-actions">${entry.hasTotp ? `<button class="icon-button entry-totp" data-id="${id}" aria-label="Show authenticator code" title="Authenticator code">${icon("key", 16)}</button>` : ""}<button class="icon-button entry-copy" data-id="${id}" aria-label="Copy password">${icon("copy", 16)}</button><button class="icon-button entry-edit" data-id="${id}" aria-label="Edit item">${icon("edit", 16)}</button><button class="icon-button entry-delete" data-id="${id}" aria-label="Delete item">${icon("trash", 16)}</button></div><div class="entry-password">${entry.hasTotp ? "Authenticator enabled" : "Password protected"}</div></article>`;
    })
    .join("")}</div>`;
  area.querySelectorAll<HTMLButtonElement>(".entry-copy").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.id) return;
      try {
        await copyText(await vaultApi.getEntryPassword(button.dataset.id));
      } catch (error) {
        fail(error);
      }
    });
  });
  area.querySelectorAll<HTMLButtonElement>(".entry-totp").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.id) void showTotp(button.dataset.id);
    });
  });
  area.querySelectorAll<HTMLButtonElement>(".entry-edit").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!button.dataset.id) return;
      try {
        openEntryModal(await vaultApi.getEntry(button.dataset.id));
      } catch (error) {
        fail(error);
      }
    });
  });
  area.querySelectorAll<HTMLButtonElement>(".entry-delete").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = state.entries.find((item) => item.id === button.dataset.id);
      if (entry && confirm(`Delete “${entry.title}” from your vault?`)) {
        void deleteEntry(entry.id);
      }
    });
  });
}

async function deleteEntry(id: string) {
  try {
    state.entries = await vaultApi.deleteEntry(id);
    renderEntries();
    toast("Password removed from your vault.");
  } catch (error) {
    fail(error);
  }
}
