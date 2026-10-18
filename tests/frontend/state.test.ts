import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyVaultSnapshot,
  clearUnlockedState,
  createAutoLock,
  getPasswordAgeLimitDays,
  setAutoLockMinutes,
  setPasswordAgeLimitDays,
  state,
} from "../../src/state";

describe("vault locking state", () => {
  beforeEach(() => {
    clearUnlockedState();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    setAutoLockMinutes(1);
  });

  it("locks at the configured deadline and resets the deadline after activity", () => {
    const onDeadline = vi.fn();
    const autoLock = createAutoLock(onDeadline);
    autoLock.start();

    vi.advanceTimersByTime(30_000);
    document.dispatchEvent(new Event("wheel"));
    vi.advanceTimersByTime(59_999);
    expect(onDeadline).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(onDeadline).toHaveBeenCalledOnce();
    autoLock.stop();
  });

  it("rechecks an expired deadline after a lifecycle event", () => {
    const onDeadline = vi.fn();
    const autoLock = createAutoLock(onDeadline);
    autoLock.start();

    vi.setSystemTime(new Date("2026-01-01T00:02:00Z"));
    window.dispatchEvent(new Event("focus"));

    expect(onDeadline).toHaveBeenCalledOnce();
    autoLock.stop();
  });

  it("clears all sensitive frontend state when the vault locks", () => {
    state.entries = [
      {
        id: "entry-1",
        title: "Mail",
        username: "person@example.com",
        website: "example.com",
        favorite: false,
        hasTotp: false,
        updatedAt: 1,
        passwordChangedAt: 1,
        passwordStrengthScore: 4,
        duplicatePassword: false,
      },
    ];
    state.generatedPassword = "temporary-secret";
    state.searchTerm = "mail";
    state.passwordVisible = true;

    clearUnlockedState();

    expect(state.entries).toEqual([]);
    expect(state.generatedPassword).toBe("");
    expect(state.searchTerm).toBe("");
    expect(state.passwordVisible).toBe(false);
    expect(getPasswordAgeLimitDays()).toBe(90);
  });

  it("defaults the password age limit to 90 days and validates changes", () => {
    expect(getPasswordAgeLimitDays()).toBe(90);
    setPasswordAgeLimitDays(120);
    expect(getPasswordAgeLimitDays()).toBe(120);
    expect(() => setPasswordAgeLimitDays(29)).toThrow(
      "Password age must be between 30 and 3650 days.",
    );
  });

  it("applies preferences returned with an unlocked vault snapshot", () => {
    applyVaultSnapshot({
      entries: [],
      preferences: { passwordAgeLimitDays: 180 },
    });

    expect(getPasswordAgeLimitDays()).toBe(180);
  });
});
