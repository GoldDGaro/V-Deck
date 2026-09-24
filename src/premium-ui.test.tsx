// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import type { ButtonItemProps } from "@decky/ui";
import type { ReactNode } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PremiumPage } from "./premium-ui";

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  import: vi.fn(),
  locations: vi.fn(),
  select: vi.fn(),
  picker: vi.fn(),
}));
vi.mock("./api", () => ({
  premiumSubscriptions: mocks.list,
  premiumImport: mocks.import,
  premiumLocations: mocks.locations,
  premiumSelect: mocks.select,
}));
vi.mock("@decky/api", () => ({
  FileSelectionType: { FILE: 0 },
  openFilePicker: mocks.picker,
}));
vi.mock("@decky/ui", () => ({
  ButtonItem: ({ children, disabled, onClick }: ButtonItemProps) => (
    <button
      disabled={disabled}
      onClick={(event) => onClick?.(event.nativeEvent)}
    >
      {children}
    </button>
  ),
  PanelSection: ({ children }: { children: ReactNode }) => (
    <section>{children}</section>
  ),
  PanelSectionRow: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));
const subscription = {
  id: "test-id",
  country: null,
  connection_id: null,
  locations: [{ code: "DE", name: "Germany" }],
};
beforeEach(() => {
  vi.resetAllMocks();
  mocks.list.mockResolvedValue({
    success: true,
    code: "OK",
    subscriptions: [],
  });
  mocks.picker.mockResolvedValue({
    path: "/home/deck/Downloads/premium.vpn",
    realpath: "/home/deck/Downloads/premium.vpn",
  });
  mocks.import.mockResolvedValue({ success: true, code: "OK", subscription });
  mocks.select.mockResolvedValue({ success: true, code: "OK" });
});
afterEach(cleanup);

it("imports subscription, shows API countries, selects once and refreshes parent", async () => {
  const imported = vi.fn().mockResolvedValue(undefined);
  render(<PremiumPage language="en" onBack={vi.fn()} onImported={imported} />);
  fireEvent.click(screen.getByText("Import subscription .vpn"));
  fireEvent.click(await screen.findByText("Germany (DE)"));
  await waitFor(() => expect(imported).toHaveBeenCalledTimes(1));
  expect(mocks.import).toHaveBeenCalledWith(
    "/home/deck/Downloads/premium.vpn",
    "/home/deck/Downloads/premium.vpn",
  );
  expect(mocks.select).toHaveBeenCalledExactlyOnceWith("test-id", "DE");
});

it("shows API error code instead of silent failure", async () => {
  mocks.import.mockResolvedValue({
    success: false,
    code: "PREMIUM_AUTH_FAILED",
  });
  render(<PremiumPage language="ru" onBack={vi.fn()} onImported={vi.fn()} />);
  fireEvent.click(screen.getByText("Импортировать подписку .vpn"));
  await screen.findByRole("alert");
  expect(screen.getByRole("alert").textContent).toContain(
    "PREMIUM_AUTH_FAILED",
  );
  expect(mocks.select).not.toHaveBeenCalled();
});

it("loads saved subscription countries without importing key again", async () => {
  mocks.list.mockResolvedValue({
    success: true,
    code: "OK",
    subscriptions: [subscription],
  });
  mocks.locations.mockResolvedValue({
    success: true,
    code: "OK",
    subscription,
  });
  render(<PremiumPage language="en" onBack={vi.fn()} onImported={vi.fn()} />);
  fireEvent.click(await screen.findByText("Subscription 1"));
  await screen.findByText("Germany (DE)");
  expect(mocks.locations).toHaveBeenCalledExactlyOnceWith("test-id");
  expect(mocks.import).not.toHaveBeenCalled();
});

it("blocks repeated clicks while configuration request is pending", async () => {
  let finish!: (value: { success: boolean; code: string }) => void;
  mocks.select.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  render(<PremiumPage language="en" onBack={vi.fn()} onImported={vi.fn()} />);
  fireEvent.click(screen.getByText("Import subscription .vpn"));
  const country = await screen.findByText("Germany (DE)");
  fireEvent.click(country);
  fireEvent.click(country);
  expect(mocks.select).toHaveBeenCalledTimes(1);
  expect((country as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("status").textContent).toContain("45");
  await act(async () =>
    finish({ success: false, code: "PREMIUM_NETWORK_FAILED" }),
  );
  expect(screen.getByRole("alert").textContent).toContain(
    "PREMIUM_NETWORK_FAILED",
  );
  expect(screen.queryByRole("status")).toBeNull();
});

it("explains uncertain config delivery without automatically replaying it", async () => {
  mocks.select.mockResolvedValue({
    success: false,
    code: "PREMIUM_REQUEST_UNCERTAIN",
  });
  render(<PremiumPage language="en" onBack={vi.fn()} onImported={vi.fn()} />);
  fireEvent.click(screen.getByText("Import subscription .vpn"));
  fireEvent.click(await screen.findByText("Germany (DE)"));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("PREMIUM_REQUEST_UNCERTAIN");
  expect(alert.textContent).toContain("Automatic replay is disabled");
  expect(mocks.select).toHaveBeenCalledExactlyOnceWith("test-id", "DE");
});
