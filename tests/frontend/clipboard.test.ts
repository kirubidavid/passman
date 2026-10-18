import { beforeEach, describe, expect, it, vi } from "vitest";

const toast = vi.hoisted(() => vi.fn());
vi.mock("../../src/ui", () => ({ toast }));

import { copyText } from "../../src/clipboard";

describe("clipboard handling", () => {
  const writeText = vi.fn<(value: string) => Promise<void>>();
  const readText = vi.fn<() => Promise<string>>();

  beforeEach(() => {
    vi.useFakeTimers();
    writeText.mockResolvedValue();
    readText.mockResolvedValue("copied-secret");
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText, writeText },
    });
  });

  it("clears copied values after 30 seconds when the clipboard is unchanged", async () => {
    await copyText("copied-secret");
    await vi.advanceTimersByTimeAsync(30_000);

    expect(writeText).toHaveBeenNthCalledWith(1, "copied-secret");
    expect(writeText).toHaveBeenNthCalledWith(2, "");
    expect(toast).toHaveBeenCalledWith(
      "Copied. Clipboard clears in 30 seconds.",
    );
  });

  it("does not erase content another application placed on the clipboard", async () => {
    readText.mockResolvedValue("newer-content");

    await copyText("copied-secret");
    await vi.advanceTimersByTimeAsync(30_000);

    expect(writeText).toHaveBeenCalledTimes(1);
  });

  it("reports clipboard write failures without logging clipboard contents", async () => {
    writeText.mockRejectedValue(new Error("permission denied"));

    await copyText("copied-secret");

    expect(toast).toHaveBeenCalledWith(
      "Clipboard access is unavailable.",
      true,
    );
  });
});
