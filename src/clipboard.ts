import { toast } from "./ui";

let clipboardTimer = 0;

export async function copyText(value: string) {
  if (!value) {
    toast("Generate a password first.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
    window.clearTimeout(clipboardTimer);
    clipboardTimer = window.setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === value) {
          await navigator.clipboard.writeText("");
        }
      } catch {
        // Clipboard read permission is optional; never log clipboard contents.
      }
    }, 30_000);
    toast("Copied. Clipboard clears in 30 seconds.");
  } catch {
    toast("Clipboard access is unavailable.", true);
  }
}
