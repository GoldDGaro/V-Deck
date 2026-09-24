import { ButtonItem, PanelSection, PanelSectionRow } from "@decky/ui";
import { FileSelectionType, openFilePicker } from "@decky/api";
import { useEffect, useRef, useState } from "react";
import {
  premiumImport,
  premiumLocations,
  premiumSelect,
  premiumSubscriptions,
} from "./api";
import { pickerRpcPaths } from "./import-flow";
import type { PremiumResponse, PremiumSubscription } from "./types";

export function PremiumPage({
  language,
  onBack,
  onImported,
}: {
  language: "ru" | "en";
  onBack: () => void;
  onImported: () => Promise<void>;
}): React.ReactElement {
  const ru = language === "ru";
  const [subscriptions, setSubscriptions] = useState<PremiumSubscription[]>([]);
  const [selected, setSelected] = useState<PremiumSubscription | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inFlight = useRef(false);
  const check = (response: PremiumResponse) => {
    if (!response.success) {
      const code = /^PREMIUM_[A-Z_]+$/.test(response.code)
        ? response.code
        : "PREMIUM_OPERATION_FAILED";
      throw new Error(code);
    }
    return response;
  };
  useEffect(() => {
    let active = true;
    void premiumSubscriptions()
      .then((response) => {
        check(response);
        if (active) setSubscriptions(response.subscriptions ?? []);
      })
      .catch(() => {
        if (active) setError("PREMIUM_LIST_FAILED");
      });
    return () => {
      active = false;
    };
  }, []);
  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      await operation();
    } catch (reason: unknown) {
      if (reason !== "User canceled") {
        const message = reason instanceof Error ? reason.message : "";
        setError(
          /^PREMIUM_[A-Z_]+$/.test(message)
            ? message
            : "PREMIUM_FRONTEND_FAILED",
        );
      }
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <PanelSection title="Amnezia Premium">
      {busy && (
        <PanelSectionRow>
          <div role="status">
            {ru
              ? "Получение данных Premium… Проверка резервных шлюзов может занять до 45 секунд."
              : "Fetching Premium data… Checking fallback gateways may take up to 45 seconds."}
          </div>
        </PanelSectionRow>
      )}
      {error && (
        <PanelSectionRow>
          <div role="alert">
            {ru ? "Не удалось выполнить операцию" : "Operation failed"}: {error}
            {error === "PREMIUM_REQUEST_UNCERTAIN" && (
              <div>
                {ru
                  ? "Запрос отправлен, но ответ не получен. Автоматический повтор отключён, чтобы не выпускать конфигурацию повторно."
                  : "The request was sent but no response arrived. Automatic replay is disabled to avoid issuing the configuration twice."}
              </div>
            )}
          </div>
        </PanelSectionRow>
      )}
      <PanelSectionRow>
        <div style={{ fontSize: 12 }}>
          {ru
            ? "Импортируйте файл ключа подписки .vpn. Выбор страны получает конфигурацию из API и использует слот устройства. Для смены страны сначала выключите VPN. Затем включите профиль в главном списке."
            : "Import the subscription key .vpn file. Selecting a country obtains a configuration from the API and uses a device slot. Disconnect VPN before changing country. Then enable the profile in the main list."}
        </div>
      </PanelSectionRow>
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const picked = await openFilePicker(
                FileSelectionType.FILE,
                "/home/deck/Downloads",
                true,
                true,
                undefined,
                ["vpn"],
                false,
                false,
              );
              const response = check(
                await premiumImport(...pickerRpcPaths(picked)),
              );
              if (!response.subscription)
                throw new Error("PREMIUM_RESPONSE_INVALID");
              setSelected(response.subscription);
              setSubscriptions((previous) => [
                ...previous.filter(
                  (item) => item.id !== response.subscription!.id,
                ),
                response.subscription!,
              ]);
            })
          }
        >
          {ru ? "Импортировать подписку .vpn" : "Import subscription .vpn"}
        </ButtonItem>
      </PanelSectionRow>
      {subscriptions.map((subscription, index) => (
        <PanelSectionRow key={subscription.id}>
          <ButtonItem
            layout="below"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const response = check(await premiumLocations(subscription.id));
                if (!response.subscription)
                  throw new Error("PREMIUM_RESPONSE_INVALID");
                setSelected(response.subscription);
              })
            }
          >{`${ru ? "Подписка" : "Subscription"} ${index + 1}${subscription.country ? ` · ${subscription.country}` : ""}`}</ButtonItem>
        </PanelSectionRow>
      ))}
      {selected?.locations.map((location) => (
        <PanelSectionRow key={location.code}>
          <ButtonItem
            layout="below"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                check(await premiumSelect(selected.id, location.code));
                await onImported();
              })
            }
          >
            {location.name} ({location.code})
          </ButtonItem>
        </PanelSectionRow>
      ))}
      <PanelSectionRow>
        <ButtonItem layout="below" disabled={busy} onClick={onBack}>
          {ru ? "Назад" : "Back"}
        </ButtonItem>
      </PanelSectionRow>
    </PanelSection>
  );
}
