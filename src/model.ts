import type { Connection, Runtime } from "./types";

export function sortConnections(connections: Connection[]): Connection[] {
  return [...connections].sort((left, right) => {
    const leftDate = left.last_used_at ?? left.created_at;
    const rightDate = right.last_used_at ?? right.created_at;
    return rightDate.localeCompare(leftDate);
  });
}

export function connectionStatus(
  connection: Connection,
  runtime: Runtime,
): Runtime["state"] {
  return runtime.connection_id === connection.id
    ? runtime.state
    : "DISCONNECTED";
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds < 0) return "—";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`;
}

export function truncateName(value: string, limit = 54): string {
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}
