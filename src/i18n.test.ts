import { describe, expect, it } from "vitest";
import { rpcErrorMessage, t } from "./i18n";

describe("localization", () => {
  it("has distinct Russian and English strings", () => {
    expect(t("ru", "addVpn")).toBe("Добавить VPN");
    expect(t("en", "addVpn")).toBe("Add VPN");
  });

  it("contains scroll-safe long security warning", () => {
    expect(t("ru", "killWarning").length).toBeGreaterThan(100);
  });

  it("localizes stable backend error codes", () => {
    expect(
      rpcErrorMessage("ru", "OPENVPN_AUTH_FAILED", "raw backend text"),
    ).toBe("Ошибка аутентификации VPN");
    expect(rpcErrorMessage("en", "CONFIG_MALFORMED")).toBe(
      "The VPN configuration is invalid or unsupported",
    );
  });
});
