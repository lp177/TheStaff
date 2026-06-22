<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { Settings } from "lucide-vue-next";
import NetworkMap from "@/components/NetworkMap.vue";
import DetailView from "@/components/DetailView.vue";
import SettingsModal from "@/components/SettingsModal.vue";
import AiChat from "@/components/AiChat.vue";
import { useDevicesStore } from "@/stores/devices";

const store = useDevicesStore();
const showSettings = ref(false);
let statusTimer: number | undefined;

onMounted(() => {
  store.connect();
  store.fetchStatus();
  statusTimer = window.setInterval(() => store.fetchStatus(), 15000);
});
onUnmounted(() => {
  store.disconnect();
  if (statusTimer) window.clearInterval(statusTimer);
});
</script>

<template>
  <div class="dash">
    <header class="topbar">
      <div class="brand">
        <img class="logo" src="/logo.png" alt="" width="32" height="32" />
        <div>
          <div class="title">TheStaff</div>
          <div class="subtitle">{{ store.status?.event || "security challenge" }}</div>
        </div>
      </div>

      <div class="stats">
        <span class="stat"><b>{{ store.totals.hosts }}</b> devices</span>
        <span class="stat state-open"><span class="dot dot-open" /> {{ store.totals.open }} open</span>
        <span class="stat state-solved"><span class="dot dot-solved" /> {{ store.totals.solved }} solved</span>
        <span class="stat state-accepted"><span class="dot dot-accepted" /> {{ store.totals.accepted }} accepted</span>
      </div>

      <div class="controls">
        <span class="conn" :class="{ live: store.connected }">
          <span class="dot" :class="store.connected ? 'dot-solved' : 'dot-open'" />
          {{ store.connected ? "live" : "reconnecting…" }}
        </span>
        <span v-if="store.status" class="mode-pill">{{ store.status.mode }} · {{ store.status.target_cidr }}</span>
        <button class="btn-primary" :disabled="store.busy.scan" @click="store.scanNow()">
          {{ store.busy.scan ? "Scanning…" : "Scan now" }}
        </button>
        <button class="gear" title="Settings" aria-label="Settings" @click="showSettings = true">
          <Settings :size="16" />
        </button>
        <RouterLink class="link" to="/">Consent page</RouterLink>
      </div>
    </header>

    <main class="canvas">
      <NetworkMap />
      <div class="legend">
        <span class="state-open"><span class="dot dot-open" /> open (fix it)</span>
        <span class="state-solved"><span class="dot dot-solved" /> solved</span>
        <span class="state-accepted"><span class="dot dot-accepted" /> accepted</span>
      </div>
    </main>

    <DetailView />
    <SettingsModal :open="showSettings" @close="showSettings = false" />
    <AiChat />
  </div>
</template>

<style scoped>
.dash { display: flex; flex-direction: column; height: 100%; }
.topbar {
  display: flex; align-items: center; gap: 1.2rem; flex-wrap: wrap;
  padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); background: var(--panel);
}
.brand { display: flex; align-items: center; gap: 0.6rem; }
.logo { width: 2rem; height: 2rem; display: block; }
.title { font-weight: 800; letter-spacing: 0.2px; }
.subtitle { font-size: 0.74rem; color: var(--muted); }
.stats { display: flex; gap: 0.9rem; flex-wrap: wrap; }
.stat { display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.85rem; }
.stat .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; }
.controls { margin-left: auto; display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
.conn { display: inline-flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; color: var(--muted); }
.conn .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; }
.mode-pill { font-size: 0.72rem; color: var(--muted); border: 1px solid var(--border); border-radius: 999px; padding: 0.1rem 0.5rem; font-family: ui-monospace, monospace; }
.gear { display: grid; place-items: center; padding: 0.4rem; line-height: 0; }
.warn { color: var(--open); font-size: 0.82rem; }
.link { font-size: 0.8rem; }
.canvas { position: relative; flex: 1; min-height: 0; }
.legend {
  position: absolute; left: 12px; bottom: 12px; display: flex; gap: 0.9rem;
  background: color-mix(in srgb, var(--panel) 85%, transparent);
  border: 1px solid var(--border); border-radius: 10px; padding: 0.4rem 0.7rem;
  font-size: 0.78rem; backdrop-filter: blur(4px);
}
.legend span { display: inline-flex; align-items: center; gap: 0.35rem; }
.legend .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; }
</style>
