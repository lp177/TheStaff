<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { MessageSquareText } from "lucide-vue-next";
import { iconFor, labelFor } from "@/lib/icons";
import { useDevicesStore } from "@/stores/devices";
import { useSettingsStore } from "@/stores/settings";
import { useChatStore } from "@/stores/chat";
import type { Cve, Port } from "@/types";

const store = useDevicesStore();
const settings = useSettingsStore();
const chat = useChatStore();
const dialog = ref<HTMLDialogElement | null>(null);

async function askAi(cve: Cve) {
  const detail = store.cveDetails[cve.id] ?? (await store.loadCveDetail(cve.id));
  if (detail) chat.open(detail);
}

const host = computed(() => store.selectedHost);
const HostIcon = computed(() => iconFor(host.value?.device_type));

const expanded = ref<Set<number>>(new Set());
const confirming = ref<number | null>(null); // cve id awaiting accept confirm
const copied = ref<string | null>(null);

watch(
  () => store.selectedHostId,
  (id) => {
    const d = dialog.value;
    if (!d) return;
    if (id != null && !d.open) d.showModal();
    else if (id == null && d.open) d.close();
  },
);

function onClose() {
  expanded.value = new Set();
  confirming.value = null;
  store.closeDetail();
}

async function toggle(cve: Cve) {
  const set = new Set(expanded.value);
  if (set.has(cve.id)) {
    set.delete(cve.id);
  } else {
    set.add(cve.id);
    if (!store.cveDetails[cve.id]) await store.loadCveDetail(cve.id);
  }
  expanded.value = set;
}

async function copy(cmd: string) {
  try {
    await navigator.clipboard.writeText(cmd);
    copied.value = cmd;
    window.setTimeout(() => (copied.value = null), 1200);
  } catch {
    /* clipboard may be blocked; ignore */
  }
}

function sevClass(cve: Cve) {
  return `sev-${cve.severity}`;
}

function resultClass(result: string) {
  if (result === "RESOLVED" || result === "LIKELY_RESOLVED") return "state-solved";
  if (result === "STILL_PRESENT") return "state-open";
  return "state-clean";
}

const portsSorted = computed<Port[]>(() => host.value?.ports ?? []);

onMounted(() => {
  // Light-dismiss fallback for browsers without <dialog closedby>
  const d = dialog.value;
  if (d && !("closedBy" in HTMLDialogElement.prototype)) {
    d.addEventListener("click", (event) => {
      if (event.target !== d) return;
      const r = d.getBoundingClientRect();
      const inside =
        r.top <= event.clientY && event.clientY <= r.top + r.height &&
        r.left <= event.clientX && event.clientX <= r.left + r.width;
      if (!inside) d.close();
    });
  }
});
</script>

<template>
  <dialog ref="dialog" closedby="any" aria-labelledby="detail-title" @close="onClose" class="scroller">
    <div v-if="host" class="detail">
      <header class="head">
        <span class="head-icon"><component :is="HostIcon" :size="26" /></span>
        <div class="head-id">
          <h2 id="detail-title">{{ host.hostname || host.ip }}</h2>
          <div class="head-sub">
            {{ labelFor(host.device_type) }} ·
            <span class="mono">{{ host.ip }}</span>
            <template v-if="host.vendor"> · {{ host.vendor }}</template>
            <template v-if="host.os_family"> · {{ host.os_family }}</template>
          </div>
        </div>
        <span class="pill" :class="`state-${host.worst_state}`">
          <span class="dot" :class="`dot-${host.worst_state}`" />{{ host.worst_state }}
        </span>
        <button class="close" @click="dialog?.close()" aria-label="Close">✕</button>
      </header>

      <div class="body scroller">
        <p v-if="!portsSorted.length" class="muted">No open ports or findings on this device. 🎉</p>

        <section v-for="port in portsSorted" :key="port.id" class="port">
          <div class="port-head">
            <div>
              <span class="mono port-num">{{ port.number }}/{{ port.protocol }}</span>
              <span class="svc">{{ port.service || "unknown" }}</span>
              <span v-if="port.product" class="prod">
                {{ port.product }}<template v-if="port.version"> {{ port.version }}</template>
              </span>
            </div>
            <span class="pill" :class="`state-${port.state}`">
              <span class="dot" :class="`dot-${port.state}`" />{{ port.state }}
            </span>
          </div>

          <!-- ports with no CVE but open: still actionable (accept / re-test) -->
          <div v-if="!port.cves.length" class="port-actions">
            <span class="muted small">Open port, no known CVE.</span>
            <button class="btn-solve small" :disabled="store.busy[`hc-port-${port.id}`]"
                    @click="store.healthcheckPort(port.id)">
              {{ store.busy[`hc-port-${port.id}`] ? "Re-testing…" : "Run healthcheck" }}
            </button>
            <button v-if="port.state === 'open'" class="btn-accept small" @click="store.acceptPort(port.id)">Accept</button>
            <button v-else class="small" @click="store.reopenPort(port.id)">Reopen</button>
          </div>
          <div v-if="store.portHealthchecks[port.id]" class="hc port-hc">
            <div class="hc-head">
              Healthcheck (tier {{ store.portHealthchecks[port.id].tier }}):
              <span class="pill" :class="resultClass(store.portHealthchecks[port.id].result)">
                {{ store.portHealthchecks[port.id].result }}
              </span>
            </div>
            <pre v-for="(a, i) in store.portHealthchecks[port.id].attempts" :key="i" class="hc-out scroller"><code>$ {{ a.command }}
{{ a.output }}</code></pre>
          </div>

          <ul class="cves">
            <li v-for="cve in port.cves" :key="cve.id" class="cve" :class="`cve-${cve.state}`">
              <div class="cve-row" @click="toggle(cve)">
                <button class="chev" :aria-expanded="expanded.has(cve.id)">
                  {{ expanded.has(cve.id) ? "▾" : "▸" }}
                </button>
                <span class="mono cve-id">{{ cve.cve_id }}</span>
                <span class="cvss" :class="sevClass(cve)">
                  {{ cve.cvss?.toFixed(1) ?? "?" }} {{ cve.severity }}
                </span>
                <span v-if="cve.is_exploit" class="exploit" title="Public exploit known">exploit</span>
                <span class="pill ml-auto" :class="`state-${cve.state}`">
                  <span class="dot" :class="`dot-${cve.state}`" />{{ cve.state }}
                </span>
              </div>

              <div v-if="expanded.has(cve.id)" class="cve-detail">
                <p class="summary">{{ cve.summary }}</p>

                <div class="actions">
                  <button class="btn-solve small" :disabled="store.busy[`hc-cve-${cve.id}`]"
                          @click="store.healthcheckCve(cve.id)">
                    {{ store.busy[`hc-cve-${cve.id}`] ? "Re-testing…" : "Run healthcheck" }}
                  </button>

                  <button v-if="settings.anyKey" class="btn-ai small" title="Discuss & verify this CVE with AI"
                          @click="askAi(cve)">
                    <MessageSquareText :size="13" /> Ask AI
                  </button>

                  <template v-if="cve.state !== 'accepted'">
                    <template v-if="confirming === cve.id">
                      <span class="confirm-q">Accept this open finding?</span>
                      <button class="btn-accept small"
                              @click="store.acceptCve(cve.id); confirming = null">Yes, accept</button>
                      <button class="small" @click="confirming = null">Cancel</button>
                    </template>
                    <button v-else class="small" @click="confirming = cve.id">Accept…</button>
                  </template>
                  <button v-else class="small" @click="store.reopenCve(cve.id)">Reopen</button>
                </div>

                <!-- healthcheck result -->
                <div v-if="store.healthchecks[cve.id]" class="hc">
                  <div class="hc-head">
                    Healthcheck (tier {{ store.healthchecks[cve.id].tier }}):
                    <span class="pill" :class="resultClass(store.healthchecks[cve.id].result)">
                      {{ store.healthchecks[cve.id].result }}
                    </span>
                  </div>
                  <pre v-for="(a, i) in store.healthchecks[cve.id].attempts" :key="i" class="hc-out scroller"><code>$ {{ a.command }}
{{ a.output }}</code></pre>
                </div>

                <!-- remediation + test commands (lazy-loaded detail) -->
                <template v-if="store.cveDetails[cve.id]">
                  <h4>How to fix</h4>
                  <ul class="advice">
                    <li v-for="(tip, i) in store.cveDetails[cve.id].remediation" :key="i">{{ tip }}</li>
                  </ul>

                  <h4>Test it yourself <span class="muted small">— detection only, non-destructive</span></h4>
                  <div v-for="(t, i) in store.cveDetails[cve.id].test_commands" :key="i" class="cmd">
                    <div class="cmd-label">{{ t.label }}</div>
                    <div class="cmd-line">
                      <code class="scroller">{{ t.command }}</code>
                      <button class="copy small" @click="copy(t.command)">
                        {{ copied === t.command ? "✓" : "copy" }}
                      </button>
                    </div>
                  </div>

                  <h4 v-if="store.cveDetails[cve.id].references.length">References</h4>
                  <ul class="refs">
                    <li v-for="(r, i) in store.cveDetails[cve.id].references" :key="i">
                      <a :href="r" target="_blank" rel="noopener noreferrer">{{ r }}</a>
                    </li>
                  </ul>
                </template>
                <p v-else class="muted small">Loading details…</p>
              </div>
            </li>
          </ul>
        </section>
      </div>
    </div>
  </dialog>
</template>

<style scoped>
.detail { display: flex; flex-direction: column; max-height: 88vh; }
.head {
  display: flex; align-items: center; gap: 0.7rem;
  padding: 1rem 1.1rem; border-bottom: 1px solid var(--border);
  position: sticky; top: 0; background: var(--panel); z-index: 2;
}
.head-icon { display: grid; place-items: center; width: 42px; height: 42px; border-radius: 10px; background: var(--panel-2); color: var(--brand); flex: none; }
.head-id { flex: 1; min-width: 0; }
.head-id h2 { margin: 0; font-size: 1.05rem; }
.head-sub { font-size: 0.78rem; color: var(--muted); }
.close { border: none; background: transparent; font-size: 1rem; padding: 0.3rem 0.5rem; }
.mono { font-family: ui-monospace, monospace; }
.ml-auto { margin-left: auto; }
.small { font-size: 0.76rem; padding: 0.28rem 0.55rem; }
.muted { color: var(--muted); }

.body { padding: 0.6rem 1.1rem 1.1rem; overflow: auto; }
.port { border: 1px solid var(--border); border-radius: 10px; margin-top: 0.7rem; overflow: hidden; }
.port-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.6rem 0.75rem; background: var(--panel-2); }
.port-num { font-weight: 700; margin-right: 0.4rem; }
.svc { color: var(--text); }
.prod { color: var(--muted); margin-left: 0.4rem; font-size: 0.85rem; }
.port-actions { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; }

.cves { list-style: none; margin: 0; padding: 0; }
.cve { border-top: 1px solid var(--border); }
.cve-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; cursor: pointer; }
.cve-row:hover { background: var(--panel-2); }
.chev { border: none; background: transparent; padding: 0 0.2rem; color: var(--muted); }
.cve-id { font-weight: 650; }
.cvss { font-size: 0.76rem; font-weight: 700; }
.exploit { font-size: 0.66rem; font-weight: 700; color: #fff; background: var(--open); padding: 0.05rem 0.4rem; border-radius: 999px; }

.cve-detail { padding: 0.2rem 0.9rem 0.9rem 1.6rem; }
.summary { margin: 0.3rem 0 0.6rem; color: var(--text); font-size: 0.88rem; line-height: 1.5; }
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
.btn-ai { display: inline-flex; align-items: center; gap: 0.3rem; color: var(--brand); border-color: color-mix(in srgb, var(--brand) 45%, transparent); }
.btn-ai:hover { background: color-mix(in srgb, var(--brand) 14%, transparent); }
.confirm-q { font-size: 0.8rem; color: var(--accepted); }
.cve-detail h4 { margin: 0.8rem 0 0.3rem; font-size: 0.82rem; }
.advice, .refs { margin: 0; padding-left: 1.1rem; font-size: 0.84rem; line-height: 1.55; }
.refs { word-break: break-all; }

.cmd { margin: 0.35rem 0; }
.cmd-label { font-size: 0.74rem; color: var(--muted); margin-bottom: 0.15rem; }
.cmd-line { display: flex; gap: 0.4rem; align-items: stretch; }
.cmd-line code { flex: 1; background: #0a0f1f; border: 1px solid var(--border); border-radius: 7px; padding: 0.4rem 0.55rem; font-family: ui-monospace, monospace; font-size: 0.78rem; overflow-x: auto; white-space: pre; }
.copy { flex: none; }

.hc { margin: 0.5rem 0; }
.port-hc { padding: 0 0.75rem 0.6rem; }
.hc-head { font-size: 0.82rem; margin-bottom: 0.3rem; display: flex; gap: 0.4rem; align-items: center; }
.hc-out { background: #0a0f1f; border: 1px solid var(--border); border-radius: 7px; padding: 0.5rem 0.6rem; font-size: 0.74rem; overflow-x: auto; max-height: 180px; overflow-y: auto; margin: 0.2rem 0; }
.hc-out code { white-space: pre-wrap; word-break: break-word; }
</style>
