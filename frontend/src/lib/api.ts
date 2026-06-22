import type { CveDetail, HealthcheckOutcome, Host, Status } from "@/types";

const TOKEN_KEY = "sm_admin_token";

export function getAdminToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* localStorage may be unavailable */
  }
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = getAdminToken();
  if (token) headers["X-Admin-Token"] = token;
  const res = await fetch(url, { headers, ...init });
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      if (body?.detail) {
        detail = ` — ${typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)}`;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new Error(`${res.status} ${res.statusText}${detail}`);
  }
  return (await res.json()) as T;
}

export interface AiModel {
  id: string;
  label: string;
}
export interface AiChatRequest {
  provider: string;
  model: string;
  key: string;
  system?: string;
  messages: { role: string; content: string }[];
}

export const api = {
  hosts: () => req<{ rev: number; hosts: Host[] }>("/api/hosts"),
  status: () => req<Status>("/api/status"),
  cveDetail: (id: number) => req<CveDetail>(`/api/cves/${id}`),
  acceptCve: (id: number) =>
    req(`/api/cves/${id}/accept`, { method: "POST", body: "{}" }),
  reopenCve: (id: number) => req(`/api/cves/${id}/reopen`, { method: "POST" }),
  healthcheckCve: (id: number) =>
    req<HealthcheckOutcome>(`/api/cves/${id}/healthcheck`, { method: "POST" }),
  acceptPort: (id: number) =>
    req(`/api/ports/${id}/accept`, { method: "POST", body: "{}" }),
  reopenPort: (id: number) => req(`/api/ports/${id}/reopen`, { method: "POST" }),
  healthcheckPort: (id: number) =>
    req<HealthcheckOutcome>(`/api/ports/${id}/healthcheck`, { method: "POST" }),
  scanNow: () => req("/api/scan/now", { method: "POST" }),
  wipe: () => req("/api/wipe", { method: "POST" }),
  addHost: (ip: string) =>
    req<Host>("/api/hosts", { method: "POST", body: JSON.stringify({ ip }) }),
  deleteHosts: (ids: number[]) =>
    req<{ deleted: number }>("/api/hosts/delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
  aiModels: (provider: string, key: string) =>
    req<{ models: AiModel[] }>("/api/ai/models", {
      method: "POST",
      body: JSON.stringify({ provider, key }),
    }),
  aiChat: (payload: AiChatRequest) =>
    req<{ content: string }>("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  consentInfo: () =>
    req<{
      mode: "wifi" | "http";
      organizer: string;
      organizer_email: string;
      ssid: string;
      event: string;
      target_cidr: string;
      opt_in_count: number;
    }>("/api/consent"),
  recordConsent: (accepted: boolean) =>
    req("/api/consent", { method: "POST", body: JSON.stringify({ accepted }) }),
};
