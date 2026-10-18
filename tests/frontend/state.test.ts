import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearUnlockedState,
  createAutoLock,
  setAutoLockMinutes,
  state,
} from "../../src/state";

describe("vault locking state", () => {
  beforeEach(() => {
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
  });
});
