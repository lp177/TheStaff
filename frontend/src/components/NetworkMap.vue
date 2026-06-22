<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { Position, SelectionMode, VueFlow, useVueFlow } from "@vue-flow/core";
import { Background } from "@vue-flow/background";
import { Controls } from "@vue-flow/controls";
import { Handle } from "@vue-flow/core";
import { Plus, X } from "lucide-vue-next";
import DeviceCard from "./DeviceCard.vue";
import { buildGraph } from "@/lib/layout";
import { internetIcon } from "@/lib/icons";
import { useDevicesStore } from "@/stores/devices";
import { useSettingsStore } from "@/stores/settings";
import { maskIp } from "@/lib/privacy";

const store = useDevicesStore();
const settings = useSettingsStore();
const { setNodes, setEdges, fitView, onNodeClick, findNode, getSelectedNodes, removeSelectedElements, setState } =
  useVueFlow();

const graph = computed(() => buildGraph(store.hosts));
let didFit = false;

watch(
  graph,
  (g) => {
    // Keep positions the user dragged; only place genuinely new nodes.
    setNodes(
      g.nodes.map((n) => {
        const existing = findNode(n.id);
        return existing ? { ...n, position: existing.position } : n;
      }),
    );
    setEdges(g.edges);
    if (!didFit && g.nodes.length > 1) {
      didFit = true;
      nextTick(() => fitView({ padding: 0.25 }));
    }
  },
  { immediate: true, deep: false },
);

onNodeClick(({ node }) => {
  if (node.type === "device") {
    const host = (node.data as any)?.host;
    if (host) store.openHost(host.id);
  }
});

// ---- rubber-band selection → delete ----
const selectedDeviceNodes = computed(() =>
  getSelectedNodes.value.filter((n) => n.type === "device"),
);
const selectedCount = computed(() => selectedDeviceNodes.value.length);

async function deleteSelected() {
  const ids = selectedDeviceNodes.value
    .map((n) => (n.data as any)?.host?.id)
    .filter((id): id is number => typeof id === "number");
  if (ids.length) await store.deleteHosts(ids);
}

function onKeydown(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  const tag = (t?.tagName || "").toLowerCase();
  if (tag === "input" || tag === "textarea" || t?.isContentEditable) return;
  // Let any open dialog (detail/settings/chat) own Escape/Delete.
  if (document.querySelector("dialog[open]")) return;
  if (e.key === "Escape") {
    if (selectedCount.value) removeSelectedElements();
  } else if (e.key === "Delete" || e.key === "Backspace") {
    if (selectedCount.value) {
      e.preventDefault();
      deleteSelected();
    }
  }
}

onMounted(() => {
  // Partial selection: a device is selected when the rubber-band touches its card
  // (not only when fully enclosed). The prop alone doesn't reliably reach the
  // store, so set it explicitly here too.
  setState({ selectionMode: SelectionMode.Partial });
  nextTick(() => fitView({ padding: 0.25 }));
  window.addEventListener("keydown", onKeydown);
});
onUnmounted(() => window.removeEventListener("keydown", onKeydown));

// ---- add device by IP ----
const showAdd = ref(false);
const newIp = ref("");
const addErr = ref<string | null>(null);
const adding = ref(false);

/** Strict IPv4 (matches the backend, which only supports IPv4 targets): four
 *  0–255 octets, no leading zeros. */
function validIp(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && (p === "0" || p[0] !== "0") && +p <= 255);
}
function openAdd() {
  showAdd.value = true;
  addErr.value = null;
  nextTick(() => document.getElementById("add-ip-input")?.focus());
}
async function addDevice() {
  if (adding.value) return; // guard double-submit
  const ip = newIp.value.trim();
  addErr.value = null;
  if (!validIp(ip)) { addErr.value = "Enter a valid IPv4 address."; return; }
  adding.value = true;
  try {
    await store.addHost(ip); // merges the returned host into the store immediately
    newIp.value = "";
    showAdd.value = false;
  } catch (e) {
    addErr.value = e instanceof Error ? e.message : "Couldn't add that host.";
  } finally {
    adding.value = false;
  }
}

const Internet = internetIcon;
const empty = computed(() => store.hosts.length === 0);
const publicIp = computed(() => maskIp(store.status?.public_ip, settings.state.privacyMode) || null);
</script>

<template>
  <div class="map">
    <!-- add device by IP -->
    <div class="map-tools">
      <button v-if="!showAdd" class="tool-btn" title="Add a device by IP (undetected host or one outside the scan range)" @click="openAdd">
        <Plus :size="15" /> Add device
      </button>
      <form v-else class="add-form" @submit.prevent="addDevice">
        <input id="add-ip-input" v-model="newIp" placeholder="device IPv4, e.g. 203.0.113.10"
               autocomplete="off" spellcheck="false" :disabled="adding" />
        <button type="submit" class="btn-primary small" :disabled="adding || !newIp.trim()">
          {{ adding ? "…" : "Add" }}
        </button>
        <button type="button" class="icon-x" aria-label="Cancel" @click="showAdd = false"><X :size="14" /></button>
      </form>
      <div v-if="showAdd && !addErr" class="add-note">Only add devices you're authorized to scan.</div>
      <div v-if="addErr" class="add-err">{{ addErr }}</div>
    </div>

    <!-- selection hint -->
    <div v-if="selectedCount" class="sel-bar">
      {{ selectedCount }} selected · <b>Del</b> remove · <b>Esc</b> clear
    </div>

    <VueFlow
      :default-viewport="{ zoom: 0.7 }"
      :min-zoom="0.15"
      :max-zoom="1.6"
      :nodes-draggable="true"
      :elevate-edges-on-select="true"
      :selection-key-code="true"
      :selection-mode="SelectionMode.Partial"
      :pan-on-drag="[1, 2]"
      :delete-key-code="null"
      fit-view-on-init
    >
      <Background pattern-color="#1e2842" :gap="26" :size="1.4" />
      <Controls :show-interactive="false" />

      <template #node-device="props">
        <DeviceCard :data="props.data" />
      </template>

      <template #node-internet>
        <div class="hub">
          <Handle type="source" :position="Position.Right" />
          <component :is="Internet" :size="28" />
          <div class="hub-label">Event network</div>
          <div
            class="hub-sub"
            :class="publicIp ? 'is-public' : 'is-private'"
            :title="publicIp ? `Public IP: ${publicIp}` : 'No public IP detected — closed network'"
          >
            {{ publicIp || "Private closed network" }}
          </div>
        </div>
      </template>
    </VueFlow>

    <div v-if="empty" class="empty">
      <p>No devices detected yet.</p>
      <p class="hint">Waiting for the first scan to complete…</p>
    </div>
  </div>
</template>

<style scoped>
.map { position: relative; width: 100%; height: 100%; }
.map-tools { position: absolute; top: 12px; left: 12px; z-index: 5; }
.tool-btn { display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.82rem;
  padding: 0.4rem 0.7rem; background: color-mix(in srgb, var(--panel) 92%, transparent);
  border: 1px solid var(--border); border-radius: 9px; backdrop-filter: blur(4px); }
.add-form { display: flex; align-items: center; gap: 0.35rem; background: color-mix(in srgb, var(--panel) 94%, transparent);
  border: 1px solid var(--border); border-radius: 9px; padding: 0.3rem 0.35rem; backdrop-filter: blur(4px); }
.add-form input { background: #0a0f1f; border: 1px solid var(--border); border-radius: 7px; color: var(--text);
  padding: 0.35rem 0.5rem; font-size: 0.82rem; font-family: ui-monospace, monospace; width: 190px; }
.add-form input:focus-visible { outline: 2px solid var(--brand); outline-offset: 1px; }
.add-form .small { font-size: 0.78rem; padding: 0.3rem 0.6rem; }
.icon-x { display: grid; place-items: center; padding: 0.3rem; border: 1px solid var(--border); background: var(--panel-2); border-radius: 7px; }
.add-err { margin-top: 0.35rem; font-size: 0.74rem; color: var(--open);
  background: color-mix(in srgb, var(--panel) 90%, transparent); padding: 0.2rem 0.45rem; border-radius: 6px; display: inline-block; }
.add-note { margin-top: 0.35rem; font-size: 0.7rem; color: var(--muted);
  background: color-mix(in srgb, var(--panel) 90%, transparent); padding: 0.2rem 0.45rem; border-radius: 6px; display: inline-block; }
.sel-bar { position: absolute; top: 12px; left: 50%; transform: translateX(-50%); z-index: 5;
  font-size: 0.78rem; color: var(--text); background: color-mix(in srgb, var(--brand) 16%, var(--panel));
  border: 1px solid color-mix(in srgb, var(--brand) 45%, transparent); border-radius: 999px;
  padding: 0.3rem 0.8rem; backdrop-filter: blur(4px); }
.sel-bar b { color: var(--brand); }
.hub {
  display: grid; place-items: center; gap: 0.25rem;
  width: 130px; height: 130px; border-radius: 50%;
  background: radial-gradient(circle at 50% 40%, var(--panel-3), var(--panel));
  border: 2px solid var(--brand);
  color: var(--brand);
  box-shadow: 0 0 30px color-mix(in srgb, var(--brand) 30%, transparent);
}
.hub-label { font-size: 0.74rem; color: var(--muted); font-weight: 600; }
.hub-sub {
  max-width: 104px; text-align: center; line-height: 1.15;
  font-size: 0.6rem; font-weight: 600; letter-spacing: 0.2px;
}
.hub-sub.is-public {
  font-family: ui-monospace, monospace; font-weight: 700;
  color: var(--text);
}
.hub-sub.is-private { color: var(--muted); opacity: 0.85; text-transform: uppercase; }
.empty {
  position: absolute; inset: 0; display: grid; place-content: center;
  text-align: center; color: var(--muted); pointer-events: none;
}
.empty .hint { font-size: 0.85rem; opacity: 0.7; }
</style>
