import { state, type GeneratorOptions } from "./state";
import { $, fail } from "./ui";
import { vaultApi } from "./vault-api";

export async function generatePassword() {
  const options: GeneratorOptions = {
    length: Number($<HTMLInputElement>("#password-length").value),
    uppercase: $<HTMLInputElement>("#opt-uppercase").checked,
    lowercase: $<HTMLInputElement>("#opt-lowercase").checked,
    numbers: $<HTMLInputElement>("#opt-numbers").checked,
    symbols: $<HTMLInputElement>("#opt-symbols").checked,
  };
  try {
    state.generatedPassword = await vaultApi.generatePassword(options);
    $("#generated-output").textContent = state.generatedPassword;
    $("#generated-output").classList.add("has-password");
  } catch (error) {
    fail(error);
  }
}
