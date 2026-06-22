import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { api } from "@/lib/api";
import type {
  CveDetail,
  HealthcheckOutcome,
  Host,
  Snapshot,
  Status,
} from "@/types";

export const useDevicesStore = defineStore("devices", () => {
  const hosts = ref<Host[]>([]);
  const rev = ref(0);
  const connected = ref(false);
  const status = ref<Status | null>(null);

  const selectedHostId = ref<number | null>(null);
  const healthchecks = ref<Record<number, HealthcheckOutcome>>({});
  const portHealthchecks = ref<Record<number, HealthcheckOutcome>>({});
  const cveDetails = ref<Record<number, CveDetail>>({});
  const busy = ref<Record<string, boolean>>({});

  let socket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let reconnectAttempts = 0;
  let manualClose = false;

  const selectedHost = computed(() =>
    hosts.value.find((h) => h.id === selectedHostId.value) ?? null,
  );

  const totals = computed(() => {
    const t = { hosts: hosts.value.length, open: 0, solved: 0, accepted: 0, cve_open: 0 };
    for (const h of hosts.value) {
      t.open += h.counts.open;
      t.solved += h.counts.solved;
      t.accepted += h.counts.accepted;
      t.cve_open += h.counts.cve_open;
    }
    return t;
  });

  function applySnapshot(snap: Snapshot) {
    if (snap.type !== "snapshot") return;
    rev.value = snap.rev;
    hosts.value = snap.hosts;
  }

  function connect() {
    // idempotent: don't open a second socket if one is connecting/open
    if (socket && socket.readyState <= WebSocket.OPEN) return;
    manualClose = false;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${proto}://${location.host}/ws`);
    socket.onopen = () => {
      connected.value = true;
      reconnectAttempts = 0;
    };
    socket.onmessage = (ev) => {
      try {
        applySnapshot(JSON.parse(ev.data));
      } catch {
        /* ignore malformed frames */
      }
    };
    socket.onclose = () => {
      connected.value = false;
      socket = null;
      if (!manualClose) scheduleReconnect();
    };
    socket.onerror = () => socket?.close();
  }

  function scheduleReconnect() {
    if (reconnectTimer != null || manualClose) return;
    const delay = Math.min(30000, 1000 * 2 ** reconnectAttempts);
    reconnectAttempts += 1;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delay);
  }

  function disconnect() {
    manualClose = true;
    if (reconnectTimer != null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    socket?.close();
  }

  async function fetchStatus() {
    try {
      status.value = await api.status();
    } catch {
      /* status is best-effort */
    }
  }

  function openHost(id: number) {
    selectedHostId.value = id;
  }
  function closeDetail() {
    selectedHostId.value = null;
  }

  async function loadCveDetail(id: number): Promise<CveDetail | null> {
    try {
      const detail = await api.cveDetail(id);
      cveDetails.value = { ...cveDetails.value, [id]: detail };
      return detail;
    } catch {
      return null;
    }
  }

  async function withBusy<T>(key: string, fn: () => Promise<T>): Promise<T | undefined> {
    busy.value = { ...busy.value, [key]: true };
    try {
      return await fn();
    } catch (e) {
      console.error(e);
      return undefined;
    } finally {
      busy.value = { ...busy.value, [key]: false };
    }
  }

  const acceptCve = (id: number) => withBusy(`cve-${id}`, () => api.acceptCve(id));
  const reopenCve = (id: number) => withBusy(`cve-${id}`, () => api.reopenCve(id));
  const acceptPort = (id: number) => withBusy(`port-${id}`, () => api.acceptPort(id));
  const reopenPort = (id: number) => withBusy(`port-${id}`, () => api.reopenPort(id));

  async function healthcheckCve(id: number) {
    const outcome = await withBusy(`hc-cve-${id}`, () => api.healthcheckCve(id));
    if (outcome) healthchecks.value = { ...healthchecks.value, [id]: outcome };
    return outcome;
  }

  async function healthcheckPort(id: number) {
    const outcome = await withBusy(`hc-port-${id}`, () => api.healthcheckPort(id));
    if (outcome) portHealthchecks.value = { ...portHealthchecks.value, [id]: outcome };
    return outcome;
  }

  async function scanNow() {
    await withBusy("scan", () => api.scanNow());
  }
  async function wipe() {
    await withBusy("wipe", () => api.wipe());
    closeDetail();
  }
  function upsertHost(host: Host) {
    const i = hosts.value.findIndex((h) => h.id === host.id);
    hosts.value = i >= 0
      ? hosts.value.map((h, j) => (j === i ? host : h))
      : [...hosts.value, host];
  }

  // Throws on failure so the caller can surface the message. Merges the returned
  // host immediately (don't depend on the WS broadcast round-trip to show it).
  async function addHost(ip: string): Promise<Host> {
    const host = await api.addHost(ip);
    upsertHost(host);
    return host;
  }

  async function deleteHosts(ids: number[]) {
    if (!ids.length) return;
    const res = await withBusy("deleteHosts", () => api.deleteHosts(ids));
    if (res) {
      const drop = new Set(ids);
      hosts.value = hosts.value.filter((h) => !drop.has(h.id)); // optimistic removal
      if (selectedHostId.value != null && drop.has(selectedHostId.value)) closeDetail();
    }
  }

  return {
    hosts, rev, connected, status, selectedHostId, healthchecks, portHealthchecks,
    cveDetails, busy, selectedHost, totals,
    connect, disconnect, fetchStatus, openHost, closeDetail, loadCveDetail,
    acceptCve, reopenCve, acceptPort, reopenPort, healthcheckCve, healthcheckPort,
    scanNow, wipe, addHost, deleteHosts,
  };
});
