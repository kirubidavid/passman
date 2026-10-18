import { beforeEach, describe, expect, it, vi } from "vitest";

const vaultApi = vi.hoisted(() => ({
  getTotpCode: vi.fn(),
}));
vi.mock("../../src/vault-api", () => ({ vaultApi }));
vi.mock("../../src/clipboard", () => ({ copyText: vi.fn() }));
vi.mock("../../src/generator", () => ({ generatePassword: vi.fn() }));

import { closeModal, showTotp } from "../../src/modal";
import { state } from "../../src/state";

describe("modal cleanup", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML =
      '<div id="modal-root"></div><div id="toast"></div>';
    state.entries = [
      {
        id: "entry-1",
        title: "Mail",
        username: "",
        website: "",
        favorite: false,
        hasTotp: true,
        updatedAt: 1,
      },
    ];
    vaultApi.getTotpCode.mockResolvedValue({
      code: "123456",
      secondsRemaining: 20,
    });
  });

  it("closes on Escape and stops the TOTP refresh interval", async () => {
    await showTotp("entry-1");
    expect(document.querySelector("#totp-code")?.textContent).toBe("123456");

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await vi.advanceTimersByTimeAsync(3_000);

    expect(document.querySelector("#modal-root")?.children).toHaveLength(0);
    expect(vaultApi.getTotpCode).toHaveBeenCalledOnce();
  });

  it("stops queued refresh work when modal content is removed", async () => {
    await showTotp("entry-1");
    closeModal();

    await vi.advanceTimersByTimeAsync(1_000);

    expect(vaultApi.getTotpCode).toHaveBeenCalledOnce();
  });

  it("shows backend errors without leaving a partial dialog", async () => {
    vaultApi.getTotpCode.mockRejectedValue(
      new Error("Authenticator unavailable"),
    );

    await showTotp("entry-1");

    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.querySelector("#toast")?.textContent).toBe(
      "Authenticator unavailable",
    );
    expect(document.querySelector("#toast")?.classList.contains("error")).toBe(
      true,
    );
  });
});
