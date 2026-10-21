import { copyText } from "./clipboard";
import { generatePassword } from "./generator";
import {
  confirmAction,
  confirmPhraseAction,
  openEntryModal,
  openSshKeyDetails,
  openSshKeyModal,
  openVaultSettings,
  showTotp,
} from "./modal";
import {
  applyVaultSnapshot,
  getPasswordAgeLimitDays,
  setPasswordAgeLimitDays,
  state,
  type VaultPreferences,
} from "./state";
import { $, escapeHtml, fail, icon, toast } from "./ui";
import { vaultApi } from "./vault-api";

interface RenderingCallbacks {
  loadDashboard(): Promise<void>;
  recoveryResetVault(confirmationPhrase: string): Promise<void>;
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
    return new URL(
      url.includes("://") ? url : `https://${url}`,
    ).hostname.replace(/^www\./, "");
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

const DAY_MS = 86_400_000;

function dateLabel(timestamp: number) {
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(timestamp);
}

export function getPasswordAgeStatus(
  passwordChangedAt: number,
  limitDays = getPasswordAgeLimitDays(),
  now = Date.now(),
) {
  const ageDays = Math.max(0, Math.floor((now - passwordChangedAt) / DAY_MS));
  if (ageDays > limitDays) {
    return {
      level: "red",
      label: "Change now",
      description: `Password is ${ageDays} days old and exceeds the ${limitDays}-day limit.`,
    };
  }
  if (ageDays >= limitDays - 30) {
    return {
      level: "yellow",
      label: "Due soon",
      description: `Password is ${ageDays} days old and approaches the ${limitDays}-day limit.`,
    };
  }
  return {
    level: "green",
    label: "Current",
    description: `Password is ${ageDays} days old and within the ${limitDays}-day limit.`,
  };
}

export function getEntryHealth(
  entry: (typeof state.entries)[number],
  limitDays = getPasswordAgeLimitDays(),
  now = Date.now(),
) {
  const ageKnown = entry.passwordChangedAt > 0;
  const derivedAge = getPasswordAgeStatus(
    ageKnown ? entry.passwordChangedAt : entry.updatedAt,
    limitDays,
    now,
  );
  const estimatedAgeDays = Math.max(
    0,
    Math.floor((now - entry.updatedAt) / DAY_MS),
  );
  const trackingStartedAt = entry.passwordAgeTrackingStartedAt ?? 0;
  const age = ageKnown
    ? { ...derivedAge, estimated: false, estimateLabel: "" }
    : {
        ...derivedAge,
        label: "Age unknown",
        description: `${trackingStartedAt > 0 ? `Age tracking began ${dateLabel(trackingStartedAt)}. ` : "Age tracking began when this vault was migrated. "}The exact password age remains unknown until the password changes. Estimated age: ${estimatedAgeDays} days based on the entry's last update.`,
        estimated: true,
        estimateLabel:
          derivedAge.level === "red"
            ? "Estimated overdue"
            : derivedAge.level === "yellow"
              ? "Estimated due soon"
              : "Estimated current",
      };
  const weak = entry.passwordStrengthScore <= 2;
  const duplicate = entry.duplicatePassword;
  return {
    age,
    weak,
    duplicate,
    hasIssue: age.estimated || age.level !== "green" || weak || duplicate,
    urgency:
      (age.level === "red" ? 100 : age.level === "yellow" ? 10 : 0) +
      (duplicate ? 40 : 0) +
      (weak ? 20 : 0) +
      (age.estimated && age.level === "green" ? 5 : 0),
  };
}

export function getPasswordHealthCounts(
  entries = state.entries,
  limitDays = getPasswordAgeLimitDays(),
  now = Date.now(),
) {
  return entries.reduce(
    (counts, entry) => {
      const health = getEntryHealth(entry, limitDays, now);
      if (health.age.level === "red") counts.expired += 1;
      else if (health.age.level === "yellow") counts.dueSoon += 1;
      if (health.duplicate) counts.duplicate += 1;
      if (health.weak) counts.weak += 1;
      return counts;
    },
    { expired: 0, dueSoon: 0, duplicate: 0, weak: 0 },
  );
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
    </main><div id="modal-root"></div>`;
  $("#auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = $<HTMLInputElement>("#master-password").value;
    const errorElement = $("#auth-error");
    errorElement.textContent = "";
    const submit = $<HTMLButtonElement>(".auth-submit");
    submit.disabled = true;
    try {
      let preferences: VaultPreferences;
      if (exists) preferences = await vaultApi.unlock(password);
      else {
        if (password !== $<HTMLInputElement>("#confirm-password").value) {
          throw new Error("Master passwords do not match.");
        }
        preferences = await vaultApi.create(password);
      }
      setPasswordAgeLimitDays(preferences.passwordAgeLimitDays);
      await callbacks.loadDashboard();
    } catch (error) {
      errorElement.textContent = String(error).replace(/^Error: /, "");
      submit.disabled = false;
    }
  });
  document
    .querySelector<HTMLButtonElement>("#reset-vault")
    ?.addEventListener("click", async () => {
      const confirmationPhrase = await confirmPhraseAction({
        title: "Recovery reset without your password?",
        description:
          "Use this only when the master password is forgotten. The encrypted vault and every saved password will be permanently deleted.",
        confirmLabel: "Recovery reset permanently",
        phrase: "RESET VAULT",
      });
      if (confirmationPhrase) {
        await callbacks.recoveryResetVault(confirmationPhrase);
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
          <button class="nav-item" data-filter="Password health">${icon("shield", 17)}<span>Password health</span><span class="nav-count" id="health-nav-count">0</span></button>
          <button class="nav-item" data-filter="SSH keys">${icon("key", 17)}<span>SSH keys</span><span class="nav-count" id="ssh-key-count">0</span></button>
        </nav>
        <div class="sidebar-rule"></div>
        <div class="sidebar-hint"><div class="hint-icon">${icon("shield", 17)}</div><strong>Private by design</strong><p>Your vault is encrypted on this device. Only you hold the key.</p></div>
        <div class="sidebar-bottom"><span class="avatar">${icon("lock", 15)}</span><div class="user-label"><strong>Personal vault</strong><span>Protected locally</span></div><button class="icon-button vault-settings-button" id="vault-settings" aria-label="Vault settings" title="Vault settings">${icon("settings", 17)}</button><button class="icon-button" id="lock-button" aria-label="Lock vault" title="Lock vault">${icon("lock", 17)}</button></div>
      </aside>
      <main class="main-content">
        <header class="topbar"><div class="breadcrumb">Vault <span>/</span> <strong id="breadcrumb-current">All items</strong></div><div class="top-actions"><span class="secure-status"><span class="status-dot"></span> Vault secured</span><button class="button button-quiet add-button" id="add-ssh-key">${icon("key", 16)}<span>New SSH key</span></button><button class="button button-primary add-button" id="add-entry">${icon("plus", 16)}<span>New password</span></button></div></header>
        <div class="content-inner">
          ${state.securityUpgradeAvailable ? `<button class="security-upgrade-banner" id="security-upgrade-banner" type="button">${icon("shield", 18)}<span><strong>Security upgrade available.</strong> Re-encrypt this vault with the current key-derivation parameters.</span></button>` : ""}
          <section class="welcome-row"><div><p class="eyebrow">YOUR PRIVATE SPACE</p><h1 id="page-title">All items <span class="title-count" id="heading-count">0</span></h1><p class="page-subtitle">Everything you need, securely in one place.</p></div><div class="header-decoration">${icon("shield", 26)}<span>Encrypted<br/>at rest</span></div></section>
          <section class="generator-card">
            <div class="generator-top"><div class="generator-title"><span class="generator-icon">${icon("spark", 19)}</span><div><h2>Password generator</h2><p>Make a strong, unique password in a click.</p></div></div><span class="generator-badge">${icon("shield", 13)} SECURE GENERATOR</span></div>
            <div class="generated-row"><code id="generated-output" class="generated-output" aria-live="polite">Generate a strong password</code><div class="generated-actions"><button class="icon-button" id="refresh-password" aria-label="Generate password" title="Generate password">${icon("refresh", 17)}</button><button class="icon-button" id="copy-generated" aria-label="Copy password" title="Copy password">${icon("copy", 17)}</button></div></div>
            <div class="generator-controls"><div class="length-control"><label for="password-length">LENGTH <strong id="length-value">20</strong></label><input id="password-length" type="range" min="8" max="64" value="20" /></div><div class="checks" role="group" aria-label="Character types"><label class="check-label"><input type="checkbox" id="opt-uppercase" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Uppercase <span aria-hidden="true">ABC</span></span></label><label class="check-label"><input type="checkbox" id="opt-lowercase" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Lowercase <span aria-hidden="true">abc</span></span></label><label class="check-label"><input type="checkbox" id="opt-numbers" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Numbers <span aria-hidden="true">123</span></span></label><label class="check-label"><input type="checkbox" id="opt-symbols" checked /><span class="checkmark" aria-hidden="true"></span><span class="check-text">Symbols <span aria-hidden="true">#$&</span></span></label></div><button class="button generate-button" id="generate-button">${icon("spark", 15)} Generate</button></div>
          </section>
          <section class="vault-section"><div class="vault-section-head"><div><h2>Your vault <span class="section-count" id="section-count">0</span></h2><p>Passwords and SSH keys, encrypted together.</p></div><div class="search-wrap">${icon("search", 16)}<input type="search" id="search-input" placeholder="Search vault..." autocomplete="off" /><kbd>⌘ K</kbd></div></div><div class="password-health-summary" aria-label="Password health summary"><span class="health-summary-item health-summary-red"><strong id="health-expired-count">0</strong> Expired</span><span class="health-summary-item health-summary-yellow"><strong id="health-due-count">0</strong> Due soon</span><span class="health-summary-item health-summary-orange"><strong id="health-duplicate-count">0</strong> Duplicate</span><span class="health-summary-item health-summary-purple"><strong id="health-weak-count">0</strong> Weak</span></div><div id="entries-area"></div></section>
        </div>
        <footer class="main-footer"><span>${icon("lock", 13)} Your data stays yours. Always.</span><span>Encrypted locally on this device</span></footer>
      </main>
    </div><div id="modal-root"></div>`;
  $("#add-entry").addEventListener("click", () => openEntryModal());
  $("#add-ssh-key").addEventListener("click", openSshKeyModal);
  $("#generate-button").addEventListener(
    "click",
    () => void generatePassword(),
  );
  $("#refresh-password").addEventListener(
    "click",
    () => void generatePassword(),
  );
  $("#copy-generated").addEventListener(
    "click",
    () => void copyText(state.generatedPassword),
  );
  $("#password-length").addEventListener("input", (event) => {
    $("#length-value").textContent = (event.target as HTMLInputElement).value;
  });
  $("#search-input").addEventListener("input", (event) => {
    state.searchTerm = (event.target as HTMLInputElement).value.toLowerCase();
    renderEntries();
  });
  document
    .querySelectorAll<HTMLButtonElement>(".nav-item")
    .forEach((button) => {
      button.addEventListener("click", () =>
        setFilter(button.dataset.filter ?? "All items"),
      );
    });
  $("#vault-settings").addEventListener("click", openVaultSettings);
  document
    .querySelector<HTMLButtonElement>("#security-upgrade-banner")
    ?.addEventListener("click", openVaultSettings);
  $("#lock-button").addEventListener("click", () => void callbacks.lockVault());
  callbacks.startAutoLock();
}

export function setFilter(filter: string) {
  state.activeFilter = filter;
  document
    .querySelectorAll<HTMLButtonElement>(".nav-item")
    .forEach((button) => {
      button.classList.toggle("active", button.dataset.filter === filter);
    });
  const title =
    filter === "Favorites"
      ? "Favorites"
      : filter === "Password health"
        ? "Password health"
        : filter === "SSH keys"
          ? "SSH keys"
          : "All items";
  $("#breadcrumb-current").textContent = title;
  const titleText = $("#page-title").firstChild;
  if (!titleText) throw new Error("Missing page title text");
  titleText.textContent = `${title} `;
  renderEntries();
}

export function renderEntries() {
  const healthCounts = getPasswordHealthCounts();
  $("#health-expired-count").textContent = String(healthCounts.expired);
  $("#health-due-count").textContent = String(healthCounts.dueSoon);
  $("#health-duplicate-count").textContent = String(healthCounts.duplicate);
  $("#health-weak-count").textContent = String(healthCounts.weak);
  $("#health-nav-count").textContent = String(
    state.entries.filter((entry) => getEntryHealth(entry).hasIssue).length,
  );
  $("#ssh-key-count").textContent = String(state.sshKeys.length);
  const filtered = state.entries.filter((entry) => {
    const matchesSearch = `${entry.title} ${entry.username} ${entry.website}`
      .toLowerCase()
      .includes(state.searchTerm);
    return (
      matchesSearch &&
      state.activeFilter !== "SSH keys" &&
      (state.activeFilter !== "Favorites" || entry.favorite) &&
      (state.activeFilter !== "Password health" ||
        getEntryHealth(entry).hasIssue)
    );
  });
  const filteredSshKeys = state.sshKeys.filter((key) => {
    const matchesSearch = `${key.title} ${key.algorithm} ${key.fingerprint}`
      .toLowerCase()
      .includes(state.searchTerm);
    return (
      matchesSearch &&
      state.activeFilter !== "Password health" &&
      (state.activeFilter !== "Favorites" || key.favorite)
    );
  });
  const visibleCount = filtered.length + filteredSshKeys.length;
  $("#total-count").textContent = String(
    state.entries.length + state.sshKeys.length,
  );
  $("#heading-count").textContent = String(visibleCount);
  $("#section-count").textContent = String(visibleCount);
  const area = $("#entries-area");
  if (visibleCount === 0) {
    const searching = state.searchTerm.length > 0;
    area.innerHTML = `<div class="empty-state"><div class="empty-illustration">${icon(searching ? "search" : state.activeFilter === "Password health" ? "shield" : "key", 26)}</div><h3>${searching ? "No matching vault items" : state.activeFilter === "Favorites" ? "No favorites yet" : state.activeFilter === "Password health" ? "No password health issues" : state.activeFilter === "SSH keys" ? "No SSH keys yet" : "Your vault is ready."}</h3><p>${searching ? "Try searching with a different name, username, or fingerprint." : state.activeFilter === "Favorites" ? "Mark an item as a favorite to see it here." : state.activeFilter === "Password health" ? "No expired, due-soon, duplicate, or weak passwords were found." : state.activeFilter === "SSH keys" ? "Generate an Ed25519 key pair to get started." : "Save a login or generate an SSH key to get started."}</p>${!searching && state.activeFilter === "All items" ? `<button class="button button-primary" id="empty-add">${icon("plus", 15)} Add your first password</button>` : ""}</div>`;
    area
      .querySelector<HTMLButtonElement>("#empty-add")
      ?.addEventListener("click", () => {
        openEntryModal();
      });
    return;
  }
  area.innerHTML = `<div class="entry-list">${filtered
    .sort((a, b) =>
      state.activeFilter === "Password health"
        ? getEntryHealth(b).urgency - getEntryHealth(a).urgency ||
          b.updatedAt - a.updatedAt
        : b.updatedAt - a.updatedAt,
    )
    .map((entry) => {
      const id = escapeHtml(entry.id);
      const health = getEntryHealth(entry);
      return `<article class="entry-card" data-entry-id="${id}"><div class="entry-monogram">${escapeHtml(favicon(entry.title))}</div><div class="entry-info"><div class="entry-title-row"><h3>${escapeHtml(entry.title)}</h3>${entry.favorite ? '<span class="favorite-star">★</span>' : ""}</div><p>${escapeHtml(entry.username || "No username")}</p></div><div class="entry-site">${entry.website ? `${icon("globe", 14)}<span>${escapeHtml(getHostname(entry.website))}</span>` : '<span class="site-empty">No website</span>'}</div><div class="entry-updated">${timeLabel(entry.updatedAt)}</div><div class="entry-row-actions">${entry.hasTotp ? `<button class="icon-button entry-totp" data-id="${id}" aria-label="Show authenticator code" title="Authenticator code">${icon("key", 16)}</button>` : ""}<button class="icon-button entry-copy" data-id="${id}" aria-label="Copy password">${icon("copy", 16)}</button><button class="icon-button entry-edit" data-id="${id}" aria-label="Edit item">${icon("edit", 16)}</button><button class="icon-button entry-delete" data-id="${id}" aria-label="Delete item">${icon("trash", 16)}</button></div><div class="entry-password"><span class="password-age password-age-${health.age.level}" title="${escapeHtml(health.age.description)}" aria-label="${escapeHtml(health.age.description)}"><span class="password-age-dot" aria-hidden="true"></span>${health.age.label}</span>${health.age.estimated ? `<span class="health-label health-label-estimate">${health.age.estimateLabel}</span>` : ""}${health.duplicate ? '<span class="health-label health-label-duplicate">Duplicate</span>' : ""}${health.weak ? `<span class="health-label health-label-weak">Weak (${entry.passwordStrengthScore}/4)</span>` : ""}<span>${entry.hasTotp ? "Authenticator enabled" : "Password protected"}</span></div></article>`;
    })
    .join("")}${filteredSshKeys
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map((key) => {
      const id = escapeHtml(key.id);
      return `<article class="entry-card ssh-key-card" data-ssh-key-id="${id}"><div class="entry-monogram">${icon("key", 18)}</div><div class="entry-info"><div class="entry-title-row"><h3>${escapeHtml(key.title)}</h3>${key.favorite ? '<span class="favorite-star">★</span>' : ""}</div><p>${escapeHtml(key.algorithm)} SSH key</p></div><div class="entry-site ssh-fingerprint"><span>${escapeHtml(key.fingerprint)}</span></div><div class="entry-updated">${timeLabel(key.updatedAt)}</div><div class="entry-row-actions"><button class="icon-button ssh-key-view" data-id="${id}" aria-label="View SSH key">${icon("eye", 16)}</button><button class="icon-button ssh-key-delete" data-id="${id}" aria-label="Delete SSH key">${icon("trash", 16)}</button></div><div class="entry-password"><span class="health-label ssh-key-label">SSH KEY</span><span>Private key encrypted in vault</span></div></article>`;
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
  area
    .querySelectorAll<HTMLButtonElement>(".entry-delete")
    .forEach((button) => {
      button.addEventListener("click", async () => {
        const entry = state.entries.find(
          (item) => item.id === button.dataset.id,
        );
        if (
          entry &&
          (await confirmAction({
            title: `Delete ${entry.title}?`,
            description:
              "This password entry will be permanently removed from your vault.",
            confirmLabel: "Delete password",
          }))
        ) {
          await deleteEntry(entry.id);
        }
      });
    });
  area
    .querySelectorAll<HTMLButtonElement>(".ssh-key-view")
    .forEach((button) => {
      button.addEventListener("click", async () => {
        if (!button.dataset.id) return;
        try {
          openSshKeyDetails(await vaultApi.getSshKey(button.dataset.id));
        } catch (error) {
          fail(error);
        }
      });
    });
  area
    .querySelectorAll<HTMLButtonElement>(".ssh-key-delete")
    .forEach((button) => {
      button.addEventListener("click", async () => {
        const key = state.sshKeys.find((item) => item.id === button.dataset.id);
        if (
          key &&
          (await confirmAction({
            title: `Delete ${key.title}?`,
            description:
              "This SSH public/private key pair will be permanently removed from your vault.",
            confirmLabel: "Delete SSH key",
          }))
        ) {
          try {
            applyVaultSnapshot(await vaultApi.deleteSshKey(key.id));
            renderEntries();
            toast("SSH key removed from your vault.");
          } catch (error) {
            fail(error);
          }
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
