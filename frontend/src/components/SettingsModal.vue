<script setup lang="ts">
import { reactive, ref, watch } from "vue";
import { Info, KeyRound, Loader2, RefreshCw, X } from "lucide-vue-next";
import { api, getAdminToken, setAdminToken } from "@/lib/api";
import { PROVIDERS, type Provider, useSettingsStore } from "@/stores/settings";
import { useDevicesStore } from "@/stores/devices";

const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{ close: [] }>();

const settings = useSettingsStore();
const devices = useDevicesStore();
const dialog = ref<HTMLDialogElement | null>(null);

const token = ref(getAdminToken());
const infoPrivacy = ref(false);
const reveal = reactive<Record<string, boolean>>({});
const discovering = reactive<Record<Provider, boolean>>({ anthropic: false, openai: false });
const discoverMsg = reactive<Record<Provider, string>>({ anthropic: "", openai: "" });
const confirmWipe = ref(false);

watch(
  () => props.open,
  (open) => {
    const d = dialog.value;
    if (!d) return;
    if (open && !d.open) {
      token.value = getAdminToken();
      confirmWipe.value = false;
      d.showModal();
    } else if (!open && d.open) {
      d.close();
    }
  },
);

async function discover(p: Provider) {
  const key = settings.state.keys[p].trim();
  if (!key) return;
  discovering[p] = true;
  discoverMsg[p] = "";
  try {
    const { models } = await api.aiModels(p, key);
    settings.setModels(p, models);
    discoverMsg[p] = models.length
      ? `Found ${models.length} model${models.length === 1 ? "" : "s"}.`
      : "No chat models found for this key.";
  } catch (e) {
    discoverMsg[p] = e instanceof Error ? e.message : String(e);
  } finally {
    discovering[p] = false;
  }
}

function saveToken() {
  setAdminToken(token.value.trim());
}

function doWipe() {
  devices.wipe();
  confirmWipe.value = false;
  emit("close");
}
</script>

<template>
  <dialog ref="dialog" closedby="any" class="scroller" aria-label="Settings" @close="emit('close')">
    <div class="settings">
      <header class="head">
        <h2>Settings</h2>
        <button class="close" aria-label="Close" @click="dialog?.close()"><X :size="18" /></button>
      </header>

      <div class="body scroller">
        <!-- ===== privacy ===== -->
        <section>
          <h3>Privacy</h3>
          <div class="privacy-row">
            <label class="toggle">
              <input type="checkbox" v-model="settings.state.privacyMode" />
              <span>Privacy mode</span>
            </label>
            <button
              class="info-btn"
              type="button"
              :aria-expanded="infoPrivacy"
              aria-label="What does privacy mode do?"
              title="Hides the last two octets of every IP — e.g. 192.168.x.x — on the diagram and in messages auto-sent to the AI."
              @click="infoPrivacy = !infoPrivacy"
            >
              <Info :size="15" />
            </button>
          </div>
          <p class="hint">Mask IPs on the diagram and in auto-sent AI messages (e.g. <code>192.168.x.x</code>).</p>
          <p v-if="infoPrivacy" class="hint detail">
            With privacy mode on, every IPv4 shows only its first two octets
            (<code>192.168.x.x</code>) on the live network diagram, and the automatic first
            message sent to the AI uses the masked address too — so a guest's full address
            isn't shown on a shared screen or sent to a third-party model. It does <strong>not</strong>
            change what is scanned or stored; the operator's own detail view and the copy-paste
            test commands still use the real address.
          </p>
        </section>

        <!-- ===== AI assistant ===== -->
        <section>
          <h3>AI assistant</h3>
          <p class="hint">
            Add a key to unlock a per-CVE chat that helps explain findings and verify fixes.
            Keys are stored only in this browser and sent per request — never saved on the server.
            Pick the radio to set the default key new chats use.
          </p>

          <div v-for="p in PROVIDERS" :key="p" class="provider">
            <label class="prov-head">
              <input
                type="radio"
                name="defaultProvider"
                :checked="settings.state.defaultProvider === p"
                :disabled="!settings.hasKey(p)"
                @change="settings.setDefaultProvider(p)"
              />
              <span class="prov-name">{{ settings.PROVIDER_LABEL[p] }}</span>
              <span v-if="settings.state.defaultProvider === p && settings.hasKey(p)" class="badge">default</span>
            </label>

            <div class="key-row">
              <input
                :type="reveal[p] ? 'text' : 'password'"
                class="key-input"
                :placeholder="p === 'anthropic' ? 'sk-ant-…' : 'sk-…'"
                :value="settings.state.keys[p]"
                autocomplete="off"
                spellcheck="false"
                @input="settings.setKey(p, ($event.target as HTMLInputElement).value)"
              />
              <button class="small" type="button" @click="reveal[p] = !reveal[p]">
                {{ reveal[p] ? "hide" : "show" }}
              </button>
              <button
                class="small"
                type="button"
                :disabled="!settings.hasKey(p) || discovering[p]"
                @click="discover(p)"
              >
                <component :is="discovering[p] ? Loader2 : RefreshCw" :size="13" :class="{ spin: discovering[p] }" />
                Discover models
              </button>
            </div>

            <div v-if="settings.state.models[p].length" class="model-row">
              <label>Model</label>
              <select
                :value="settings.modelFor(p)"
                @change="settings.setModel(p, ($event.target as HTMLSelectElement).value)"
              >
                <option v-for="m in settings.state.models[p]" :key="m.id" :value="m.id">{{ m.label }}</option>
              </select>
            </div>
            <p v-if="discoverMsg[p]" class="discover-msg">{{ discoverMsg[p] }}</p>
          </div>
        </section>

        <!-- ===== operator token (moved from the topbar) ===== -->
        <section>
          <h3><KeyRound :size="14" /> Operator token</h3>
          <p class="hint">
            Optional. When the server runs with <code>THESTAFF_ADMIN_TOKEN</code>, mutating
            actions (scan, accept, healthcheck, wipe, AI) require this token.
          </p>
          <div class="key-row">
            <input
              :type="reveal.token ? 'text' : 'password'"
              class="key-input"
              placeholder="operator token"
              v-model="token"
              autocomplete="off"
              spellcheck="false"
              @change="saveToken"
            />
            <button class="small" type="button" @click="reveal.token = !reveal.token">
              {{ reveal.token ? "hide" : "show" }}
            </button>
            <button class="small btn-primary" type="button" @click="saveToken">Save</button>
          </div>
        </section>

        <!-- ===== danger zone (moved from the topbar) ===== -->
        <section>
          <h3>Danger zone</h3>
          <p class="hint">Delete every collected host, port, and finding. Run this at the end of an event.</p>
          <template v-if="confirmWipe">
            <span class="warn">Delete all collected data?</span>
            <button class="btn-danger small" @click="doWipe">Confirm wipe</button>
            <button class="small" @click="confirmWipe = false">Cancel</button>
          </template>
          <button v-else class="btn-danger small" @click="confirmWipe = true">Wipe all data</button>
        </section>
      </div>
    </div>
  </dialog>
</template>

<style scoped>
.settings { display: flex; flex-direction: column; max-height: 86vh; width: min(560px, 94vw); }
.head { display: flex; align-items: center; justify-content: space-between; padding: 0.9rem 1.1rem; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--panel); }
.head h2 { margin: 0; font-size: 1.05rem; }
.close { border: none; background: transparent; padding: 0.3rem; color: var(--muted); display: grid; place-items: center; }
.body { padding: 0.4rem 1.1rem 1.1rem; overflow: auto; }
section { padding: 0.9rem 0; border-bottom: 1px solid var(--border); }
section:last-child { border-bottom: none; }
h3 { margin: 0 0 0.3rem; font-size: 0.9rem; color: var(--brand); display: flex; align-items: center; gap: 0.35rem; }
.hint { margin: 0 0 0.7rem; font-size: 0.78rem; color: var(--muted); line-height: 1.5; }
.hint code { font-family: ui-monospace, monospace; }
.hint.detail { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 0.5rem 0.6rem; margin-top: 0.5rem; }
.privacy-row { display: flex; align-items: center; gap: 0.5rem; }
.toggle { display: inline-flex; align-items: center; gap: 0.45rem; cursor: pointer; font-weight: 600; font-size: 0.9rem; }
.toggle input { width: 1rem; height: 1rem; }
.info-btn { border: none; background: transparent; color: var(--muted); display: grid; place-items: center; padding: 0.15rem; cursor: pointer; }
.info-btn:hover, .info-btn[aria-expanded="true"] { color: var(--brand); }
.provider { padding: 0.55rem 0; }
.provider + .provider { border-top: 1px dashed var(--border); }
.prov-head { display: flex; align-items: center; gap: 0.45rem; cursor: pointer; }
.prov-name { font-weight: 600; font-size: 0.9rem; }
.badge { font-size: 0.62rem; font-weight: 700; text-transform: uppercase; color: var(--brand); border: 1px solid color-mix(in srgb, var(--brand) 45%, transparent); border-radius: 999px; padding: 0.02rem 0.4rem; }
.key-row { display: flex; gap: 0.4rem; align-items: center; margin-top: 0.45rem; flex-wrap: wrap; }
.key-input { flex: 1; min-width: 180px; background: #0a0f1f; border: 1px solid var(--border); border-radius: 7px; color: var(--text); padding: 0.4rem 0.55rem; font-family: ui-monospace, monospace; font-size: 0.8rem; }
.key-input:focus-visible { outline: 2px solid var(--brand); outline-offset: 1px; }
.model-row { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.82rem; }
.model-row select { background: var(--panel-2); color: var(--text); border: 1px solid var(--border); border-radius: 7px; padding: 0.3rem 0.4rem; font-size: 0.82rem; max-width: 320px; }
.discover-msg { margin: 0.4rem 0 0; font-size: 0.74rem; color: var(--muted); }
.warn { color: var(--open); font-size: 0.82rem; margin-right: 0.5rem; }
.small { font-size: 0.76rem; padding: 0.3rem 0.55rem; display: inline-flex; align-items: center; gap: 0.3rem; }
.spin { animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
