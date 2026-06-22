<script setup lang="ts">
import { computed } from "vue";
import { Handle, Position } from "@vue-flow/core";
import { iconFor, labelFor } from "@/lib/icons";
import { useSettingsStore } from "@/stores/settings";
import { maskIp } from "@/lib/privacy";
import type { Host } from "@/types";

const props = defineProps<{ data: { host: Host } }>();
const settings = useSettingsStore();
const host = computed(() => props.data.host);
const Icon = computed(() => iconFor(host.value.device_type));
const ip = computed(() => maskIp(host.value.ip, settings.state.privacyMode));
const title = computed(() => host.value.hostname || ip.value);
</script>

<template>
  <div class="device-card" :class="`card-${host.worst_state}`">
    <Handle type="target" :position="Position.Left" />
    <div class="card-head">
      <span class="icon"><component :is="Icon" :size="22" /></span>
      <div class="ident">
        <div class="name" :title="title">{{ title }}</div>
        <div class="sub">{{ labelFor(host.device_type) }}</div>
      </div>
    </div>
    <div class="meta">
      <span class="ip">{{ ip }}</span>
      <span v-if="host.vendor" class="vendor">· {{ host.vendor }}</span>
    </div>
    <div class="chips">
      <span v-if="host.counts.open" class="pill state-open">
        <span class="dot dot-open" />{{ host.counts.open }} open
      </span>
      <span v-if="host.counts.accepted" class="pill state-accepted">
        <span class="dot dot-accepted" />{{ host.counts.accepted }} accepted
      </span>
      <span v-if="host.counts.solved" class="pill state-solved">
        <span class="dot dot-solved" />{{ host.counts.solved }} solved
      </span>
      <span v-if="!host.ports.length" class="pill state-clean">
        <span class="dot dot-clean" />no findings
      </span>
    </div>
  </div>
</template>

<style scoped>
.device-card {
  width: 210px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 4px solid var(--clean);
  border-radius: var(--radius);
  padding: 0.7rem 0.8rem;
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
}
.card-open    { border-left-color: var(--open);     box-shadow: 0 0 0 1px color-mix(in srgb, var(--open) 35%, transparent), 0 6px 20px rgba(0,0,0,0.35); }
.card-solved  { border-left-color: var(--solved);   box-shadow: 0 0 0 1px color-mix(in srgb, var(--solved) 35%, transparent), 0 6px 20px rgba(0,0,0,0.35); }
.card-accepted{ border-left-color: var(--accepted); box-shadow: 0 0 0 1px color-mix(in srgb, var(--accepted) 35%, transparent), 0 6px 20px rgba(0,0,0,0.35); }
.card-clean   { border-left-color: var(--clean); }

.card-head { display: flex; align-items: center; gap: 0.55rem; }
.icon {
  display: grid; place-items: center;
  width: 36px; height: 36px; flex: none;
  border-radius: 9px; background: var(--panel-2); color: var(--brand);
}
.ident { min-width: 0; }
.name { font-weight: 650; font-size: 0.95rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sub { font-size: 0.72rem; color: var(--muted); }
.meta { margin-top: 0.4rem; font-size: 0.74rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ip { font-family: ui-monospace, monospace; color: var(--text); }
.chips { margin-top: 0.5rem; display: flex; flex-wrap: wrap; gap: 0.3rem; }
</style>
