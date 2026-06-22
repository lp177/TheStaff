<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import { Bot, Check, Copy, CopyCheck, Maximize2, Minimize2, RotateCcw, Send, Trash2, User, X } from "lucide-vue-next";
import { useChatStore } from "@/stores/chat";
import { type Provider, useSettingsStore } from "@/stores/settings";
import { maskIp } from "@/lib/privacy";

const chat = useChatStore();
const settings = useSettingsStore();
const dialog = ref<HTMLDialogElement | null>(null);
const body = ref<HTMLDivElement | null>(null);
const draft = ref("");
const fullscreen = ref(false);

function toggleFull() {
  fullscreen.value = !fullscreen.value;
  scrollDown();
}

const cve = computed(() => chat.activeCve);
const messages = computed(() => (cve.value ? chat.messagesFor(cve.value.id) : []));
const models = computed(() => (chat.provider ? settings.state.models[chat.provider] : []));
const hasMessages = computed(() => messages.value.some((m) => !m.hint));
const hostIp = computed(() => maskIp(cve.value?.host_ip, settings.state.privacyMode));

const copied = ref<string | null>(null);
async function copyText(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text);
    copied.value = key;
    window.setTimeout(() => {
      if (copied.value === key) copied.value = null;
    }, 1200);
  } catch {
    /* clipboard may be blocked */
  }
}

function copyConversation() {
  const text = messages.value
    .filter((m) => !m.hint)
    .map((m) => `${m.role === "user" ? "You" : "AI"}:\n${m.content}`)
    .join("\n\n———\n\n");
  copyText(text, "all");
}

function clearHistory() {
  if (cve.value) chat.clearHistory(cve.value.id);
}

watch(
  () => chat.activeCve,
  async (c) => {
    const d = dialog.value;
    if (!d) return;
    if (c && !d.open) {
      d.showModal();
      await scrollDown();
    } else if (!c && d.open) {
      d.close();
    }
  },
);

watch(
  () => [messages.value.length, chat.sending],
  () => scrollDown(),
);

async function scrollDown() {
  await nextTick();
  if (body.value) body.value.scrollTop = body.value.scrollHeight;
}

function onProvider(e: Event) {
  const p = (e.target as HTMLSelectElement).value as Provider;
  chat.setProviderModel(p, settings.modelFor(p));
  chat.ensureStarted();
}
function onModel(e: Event) {
  if (!chat.provider) return;
  const id = (e.target as HTMLInputElement | HTMLSelectElement).value.trim();
  // Persist the choice so future chats (and this one) reuse it.
  settings.setModel(chat.provider, id);
  chat.setProviderModel(chat.provider, id);
  chat.ensureStarted();
}

function submit() {
  if (!cve.value || !draft.value.trim() || chat.sending) return;
  const id = cve.value.id;
  const text = draft.value;
  draft.value = "";
  chat.send(id, text);
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    submit();
  }
}
</script>

<template>
  <dialog ref="dialog" closedby="any" class="scroller" :class="{ full: fullscreen }" aria-label="Ask AI about this finding" @close="chat.close()">
    <div v-if="cve" class="chat">
      <header class="head">
        <span class="head-icon"><Bot :size="20" /></span>
        <div class="head-id">
          <h2>Ask AI</h2>
          <div class="head-sub mono">{{ cve.cve_id }}<template v-if="hostIp"> · {{ hostIp }}</template></div>
        </div>

        <div class="switch">
          <select v-if="settings.configuredProviders.length > 1" :value="chat.provider ?? ''" @change="onProvider">
            <option v-for="p in settings.configuredProviders" :key="p" :value="p">{{ settings.PROVIDER_LABEL[p] }}</option>
          </select>
          <select v-if="models.length" :value="chat.model" @change="onModel" class="model-sel">
            <option v-for="m in models" :key="m.id" :value="m.id">{{ m.label }}</option>
          </select>
          <input v-else class="model-input" :value="chat.model" placeholder="model id" @change="onModel" />
        </div>

        <button class="icon-btn" :title="copied === 'all' ? 'Copied!' : 'Copy whole conversation'"
                aria-label="Copy whole conversation" :disabled="!hasMessages" @click="copyConversation">
          <component :is="copied === 'all' ? CopyCheck : Copy" :size="16" />
        </button>
        <button class="icon-btn" title="Clear conversation history" aria-label="Clear conversation history"
                :disabled="!hasMessages || chat.sending" @click="clearHistory">
          <Trash2 :size="16" />
        </button>
        <button
          class="icon-btn"
          :title="fullscreen ? 'Restore size' : 'Full screen'"
          :aria-label="fullscreen ? 'Restore size' : 'Full screen'"
          @click="toggleFull"
        >
          <component :is="fullscreen ? Minimize2 : Maximize2" :size="16" />
        </button>
        <button class="icon-btn" title="Restart conversation" :disabled="chat.sending" @click="chat.restart()"><RotateCcw :size="16" /></button>
        <button class="icon-btn" aria-label="Close" @click="dialog?.close()"><X :size="18" /></button>
      </header>

      <div ref="body" class="body scroller">
        <div v-for="(m, i) in messages" :key="i" class="msg" :class="m.role">
          <span class="avatar"><component :is="m.role === 'user' ? User : Bot" :size="15" /></span>
          <div class="bubble-wrap">
            <div class="bubble" :class="{ err: m.error, hint: m.hint }">{{ m.content }}</div>
            <button
              v-if="!m.hint"
              class="msg-copy"
              :title="copied === 'msg-' + i ? 'Copied!' : 'Copy message'"
              :aria-label="'Copy message'"
              @click="copyText(m.content, 'msg-' + i)"
            >
              <component :is="copied === 'msg-' + i ? Check : Copy" :size="12" />
            </button>
          </div>
        </div>
        <div v-if="chat.sending" class="msg assistant">
          <span class="avatar"><Bot :size="15" /></span>
          <div class="bubble typing"><span /><span /><span /></div>
        </div>
      </div>

      <footer class="composer">
        <textarea
          v-model="draft"
          rows="2"
          placeholder="Ask a follow-up… (Enter to send, Shift+Enter for a new line)"
          :disabled="chat.sending"
          @keydown="onKeydown"
        ></textarea>
        <button class="btn-primary send" :disabled="!draft.trim() || chat.sending" @click="submit">
          <Send :size="16" />
        </button>
      </footer>
    </div>
  </dialog>
</template>

<style scoped>
/* size the dialog itself (overrides the global dialog width); .chat fills it */
dialog { width: min(760px, 96vw); max-width: min(760px, 96vw); max-height: 96vh; transition: width 0.15s ease, max-width 0.15s ease; }
dialog.full { width: 96vw; max-width: 96vw; }
.chat { display: flex; flex-direction: column; height: min(82vh, 760px); width: 100%; transition: height 0.15s ease; }
dialog.full .chat { height: 94vh; }
.head { display: flex; align-items: center; gap: 0.6rem; padding: 0.7rem 0.9rem; border-bottom: 1px solid var(--border); background: var(--panel); flex: none; }
.head-icon { display: grid; place-items: center; width: 36px; height: 36px; border-radius: 9px; background: var(--panel-2); color: var(--brand); flex: none; }
.head-id { flex: 1; min-width: 0; }
.head-id h2 { margin: 0; font-size: 0.98rem; }
.head-sub { font-size: 0.72rem; color: var(--muted); }
.mono { font-family: ui-monospace, monospace; }
.switch { display: flex; gap: 0.35rem; align-items: center; }
.switch select, .model-input { background: var(--panel-2); color: var(--text); border: 1px solid var(--border); border-radius: 7px; padding: 0.25rem 0.4rem; font-size: 0.74rem; max-width: 200px; }
.model-input { width: 150px; }
.icon-btn { border: none; background: transparent; color: var(--muted); padding: 0.3rem; display: grid; place-items: center; }
.icon-btn:hover:not(:disabled) { color: var(--text); }
.icon-btn:disabled { opacity: 0.35; cursor: not-allowed; }

.body { flex: 1; overflow-y: auto; padding: 0.9rem; display: flex; flex-direction: column; gap: 0.8rem; }
.msg { display: flex; gap: 0.5rem; align-items: flex-start; max-width: 92%; }
.msg.user { align-self: flex-end; flex-direction: row-reverse; }
.bubble-wrap { position: relative; min-width: 0; }
.msg-copy {
  position: absolute; top: 4px; right: 4px;
  border: 1px solid var(--border); background: var(--panel); color: var(--muted);
  border-radius: 6px; padding: 0.15rem; display: grid; place-items: center;
  opacity: 0; transition: opacity 0.12s ease;
}
.bubble-wrap:hover .msg-copy { opacity: 0.85; }
.msg-copy:hover { opacity: 1; color: var(--text); }
.avatar { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; flex: none; background: var(--panel-3); color: var(--muted); margin-top: 0.1rem; }
.msg.user .avatar { background: var(--brand); color: #06112e; }
.bubble { background: var(--panel-2); border: 1px solid var(--border); border-radius: 12px; padding: 0.55rem 0.75rem; font-size: 0.86rem; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
.msg.user .bubble { background: color-mix(in srgb, var(--brand) 18%, var(--panel-2)); border-color: color-mix(in srgb, var(--brand) 40%, transparent); }
.bubble.err { color: var(--open); border-color: #5a2230; background: color-mix(in srgb, var(--open) 12%, var(--panel)); }
.bubble.hint { color: var(--muted); font-style: italic; border-style: dashed; }
.typing { display: inline-flex; gap: 4px; }
.typing span { width: 6px; height: 6px; border-radius: 50%; background: var(--muted); animation: blink 1.2s infinite both; }
.typing span:nth-child(2) { animation-delay: 0.2s; }
.typing span:nth-child(3) { animation-delay: 0.4s; }
@keyframes blink { 0%, 80%, 100% { opacity: 0.25; } 40% { opacity: 1; } }

.composer { display: flex; gap: 0.5rem; padding: 0.6rem 0.7rem; border-top: 1px solid var(--border); background: var(--panel); flex: none; }
.composer textarea { flex: 1; resize: none; background: #0a0f1f; border: 1px solid var(--border); border-radius: 9px; color: var(--text); padding: 0.5rem 0.6rem; font: inherit; font-size: 0.86rem; line-height: 1.4; }
.composer textarea:focus-visible { outline: 2px solid var(--brand); outline-offset: 1px; }
.send { flex: none; align-self: stretch; display: grid; place-items: center; padding: 0 0.8rem; }
</style>
