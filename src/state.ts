export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  website: string;
  favorite: boolean;
  hasTotp: boolean;
  updatedAt: number;
  passwordChangedAt: number;
}

export interface EntryDetails extends EntrySummary {
  password: string;
  notes: string;
}

export interface EntryInput {
  id: string;
  title: string;
  username: string;
  password: string;
  website: string;
  notes: string;
  favorite: boolean;
  totpSecret: null;
  updatedAt: number;
  passwordChangedAt: number;
}

export interface Status {
  exists: boolean;
  unlocked: boolean;
  entryCount: number;
}

export interface GeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

export interface TotpResult {
  code: string;
  secondsRemaining: number;
}

export const AUTO_LOCK_OPTIONS = [1, 5, 15, 30, 60] as const;
const AUTO_LOCK_STORAGE_KEY = "passman.autoLockMinutes";
const DEFAULT_AUTO_LOCK_MINUTES = 5;
const PASSWORD_AGE_STORAGE_KEY = "passman.passwordAgeLimitDays";
export const DEFAULT_PASSWORD_AGE_LIMIT_DAYS = 90;
export const MIN_PASSWORD_AGE_LIMIT_DAYS = 30;
export const MAX_PASSWORD_AGE_LIMIT_DAYS = 3_650;

export const state = {
  entries: [] as EntrySummary[],
  activeFilter: "All items",
  searchTerm: "",
  generatedPassword: "",
  passwordVisible: false,
};

export function clearUnlockedState() {
  state.entries = [];
  state.generatedPassword = "";
  state.searchTerm = "";
  state.passwordVisible = false;
}

export function getAutoLockMinutes() {
  const stored = Number(localStorage.getItem(AUTO_LOCK_STORAGE_KEY));
  return AUTO_LOCK_OPTIONS.includes(
    stored as (typeof AUTO_LOCK_OPTIONS)[number],
  )
    ? stored
    : DEFAULT_AUTO_LOCK_MINUTES;
}

export function setAutoLockMinutes(minutes: number) {
  localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(minutes));
}

export function getPasswordAgeLimitDays() {
  const stored = Number(localStorage.getItem(PASSWORD_AGE_STORAGE_KEY));
  return Number.isInteger(stored) &&
    stored >= MIN_PASSWORD_AGE_LIMIT_DAYS &&
    stored <= MAX_PASSWORD_AGE_LIMIT_DAYS
    ? stored
    : DEFAULT_PASSWORD_AGE_LIMIT_DAYS;
}

export function setPasswordAgeLimitDays(days: number) {
  if (
    !Number.isInteger(days) ||
    days < MIN_PASSWORD_AGE_LIMIT_DAYS ||
    days > MAX_PASSWORD_AGE_LIMIT_DAYS
  ) {
    throw new Error(
      `Password age must be between ${MIN_PASSWORD_AGE_LIMIT_DAYS} and ${MAX_PASSWORD_AGE_LIMIT_DAYS} days.`,
    );
  }
  localStorage.setItem(PASSWORD_AGE_STORAGE_KEY, String(days));
}

export function createAutoLock(onDeadline: () => void) {
  let timer = 0;
  let lastActivityAt = Date.now();
  let active = false;

  const schedule = () => {
    if (!active) return;
    window.clearTimeout(timer);
    const remaining =
      getAutoLockMinutes() * 60_000 - (Date.now() - lastActivityAt);
    if (remaining <= 0) {
      onDeadline();
      return;
    }
    timer = window.setTimeout(checkDeadline, remaining);
  };
  const checkDeadline = () => {
    if (!active) return;
    if (Date.now() - lastActivityAt >= getAutoLockMinutes() * 60_000)
      onDeadline();
    else schedule();
  };
  const recordActivity = () => {
    if (!active) return;
    lastActivityAt = Date.now();
    schedule();
  };
  const lifecycleChange = () => checkDeadline();

  return {
    start() {
      if (active) return;
      active = true;
      lastActivityAt = Date.now();
      document.addEventListener("pointerdown", recordActivity, {
        passive: true,
      });
      document.addEventListener("touchstart", recordActivity, {
        passive: true,
      });
      document.addEventListener("keydown", recordActivity);
      document.addEventListener("wheel", recordActivity, { passive: true });
      document.addEventListener("scroll", recordActivity, {
        passive: true,
        capture: true,
      });
      document.addEventListener("visibilitychange", lifecycleChange);
      window.addEventListener("blur", lifecycleChange);
      window.addEventListener("focus", lifecycleChange);
      window.addEventListener("pageshow", lifecycleChange);
      schedule();
    },
    stop() {
      active = false;
      window.clearTimeout(timer);
      document.removeEventListener("pointerdown", recordActivity);
      document.removeEventListener("touchstart", recordActivity);
      document.removeEventListener("keydown", recordActivity);
      document.removeEventListener("wheel", recordActivity);
      document.removeEventListener("scroll", recordActivity, true);
      document.removeEventListener("visibilitychange", lifecycleChange);
      window.removeEventListener("blur", lifecycleChange);
      window.removeEventListener("focus", lifecycleChange);
      window.removeEventListener("pageshow", lifecycleChange);
    },
    recordActivity,
  };
}
