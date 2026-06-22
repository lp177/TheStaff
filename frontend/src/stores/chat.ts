import { defineStore } from "pinia";
import { ref } from "vue";
import { api } from "@/lib/api";
import { maskIp } from "@/lib/privacy";
import type { CveDetail } from "@/types";
import { type Provider, useSettingsStore } from "./settings";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  error?: boolean; // upstream/proxy error
  hint?: boolean; // local guidance (e.g. "pick a model") — not sent upstream
}

const LS_KEY = "thestaff_ai_chats_v1";

const SYSTEM_PROMPT =
  "You are a senior security engineer assisting an operator running an AUTHORIZED, " +
  "consent-based security-awareness event on their own isolated event network. Every " +
  "target device's owner has explicitly opted in. Your role is defensive: help the " +
  "operator understand each CVE and VERIFY whether a specific in-scope device is patched " +
  "and no longer exploitable, using non-destructive detection (version/banner/config " +
  "checks, safe scans). Be precise and practical — give real commands and clear pass/fail " +
  "criteria. Keep scope to the single in-scope host the operator names. Do not assist with " +
  "targeting systems outside this authorized, consented context.";

function loadConvos(): Record<number, ChatMessage[]> {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) || "{}");
  } catch {
    return {};
  }
}

/** First message — sent automatically AS the operator — packing everything the
 *  scanner knows about the finding (including the data source / "database origin"). */
function buildInitialMessage(d: CveDetail, privacy: boolean): string {
  const p = d.port;
  const svc = p
    ? `${p.service ?? "?"}${p.product ? ` (${p.product}${p.version ? ` ${p.version}` : ""})` : ""} on ${p.number}/${p.protocol}`
    : null;
  const maskedHost = maskIp(d.host_ip, privacy);
  const ip = maskedHost || "the target IP";
  const lines: (string | null)[] = [
    'I run an authorized, consent-based security-awareness event ("TheStaff"). A ' +
      "participant opted in and I'm checking ONE of their devices on our own event LAN to " +
      "confirm a fix — this is defensive patch-verification, not an attack on a third party.",
    "",
    "Everything our scanner recorded for this finding:",
    `- CVE: ${d.cve_id}`,
    `- CVSS: ${d.cvss ?? "?"} (${d.severity})`,
    d.summary ? `- Title / description: ${d.summary}` : null,
    d.category ? `- Category: ${d.category}` : null,
    `- Public exploit known: ${d.is_exploit ? "yes" : "no"}`,
    d.fixed_version ? `- First fixed in version: ${d.fixed_version}` : null,
    `- Data source (database origin): ${d.source ?? "unknown"}`,
    `- Current status in our tool: ${d.state}`,
    svc ? `- Affected service: ${svc}` : null,
    p?.cpe ? `- CPE: ${p.cpe}` : null,
    d.host_ip ? `- Target host IP (in scope, opted-in): ${maskedHost}` : null,
    d.references.length ? `- References: ${d.references.join(", ")}` : null,
    "",
    "Please:",
    "1. Explain this CVE in plain language — what it is and why it matters.",
    `2. Show non-destructive ways to check whether this CVE is still present and exploitable on ${ip} — safe detection (version/banner/config checks, safe nmap NSE), both from the device itself and from another host on the LAN — so I can tell whether it's still a real risk here.`,
    "3. Give concrete commands to confirm the device is patched and the issue is no longer exploitable — and what output proves it's fixed.",
    "4. Note any caveats so I can be confident before marking it resolved.",
  ];
  return lines.filter((l) => l !== null).join("\n");
}

export const useChatStore = defineStore("chat", () => {
  const settings = useSettingsStore();
  const conversations = ref<Record<number, ChatMessage[]>>(loadConvos());
  const activeCve = ref<CveDetail | null>(null);
  const sending = ref(false);
  // Per-session provider/model for the open chat (defaults to the settings'
  // active provider; switchable from the chat header).
  const provider = ref<Provider | null>(null);
  const model = ref<string>("");

  function persist() {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(conversations.value));
    } catch {
      /* ignore */
    }
  }

  function messagesFor(id: number): ChatMessage[] {
    return conversations.value[id] ?? [];
  }

  function hasRealReply(id: number): boolean {
    return messagesFor(id).some((m) => m.role === "assistant" && !m.error && !m.hint);
  }

  function pushHint(id: number, content: string) {
    conversations.value[id] = [...messagesFor(id), { role: "assistant", content, hint: true }];
    persist();
  }

  async function complete(id: number) {
    // Drop any transient hint bubbles before (re)sending.
    conversations.value[id] = messagesFor(id).filter((m) => !m.hint);
    const p = provider.value;
    const key = p ? settings.state.keys[p].trim() : "";
    if (!p || !key) {
      pushHint(id, "No API key configured — open Settings (⚙) and add a Claude or OpenAI key.");
      return;
    }
    if (!model.value.trim()) {
      pushHint(
        id,
        "Choose a model to send — open Settings (⚙) → “Discover models”, or type a model id in the header above. It sends automatically once a model is set, or press ↻ Restart.",
      );
      return;
    }
    sending.value = true;
    try {
      const res = await api.aiChat({
        provider: p,
        model: model.value,
        key,
        system: SYSTEM_PROMPT,
        messages: messagesFor(id)
          .filter((m) => !m.error && !m.hint)
          .map((m) => ({ role: m.role, content: m.content })),
      });
      conversations.value[id] = [...messagesFor(id), { role: "assistant", content: res.content }];
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      conversations.value[id] = [...messagesFor(id), { role: "assistant", content: msg, error: true }];
    } finally {
      sending.value = false;
      persist();
    }
  }

  async function open(cve: CveDetail) {
    activeCve.value = cve;
    provider.value = settings.activeProvider;
    model.value = settings.activeModel;
    // Ask the AI only the FIRST time this CVE's chat is opened. If any saved
    // history already exists, just display it — never auto-re-ask, so an
    // expensive conversation is never re-run on reopen. Use Restart (↻) to
    // deliberately start over.
    if (messagesFor(cve.id).length === 0) {
      conversations.value[cve.id] = [{ role: "user", content: buildInitialMessage(cve, settings.state.privacyMode) }];
      persist();
      await complete(cve.id); // first question (stages a hint if no key/model yet)
    }
  }

  function close() {
    activeCve.value = null;
  }

  /** Delete this CVE's saved conversation entirely (no re-ask). */
  function clearHistory(id: number) {
    const next = { ...conversations.value };
    delete next[id];
    conversations.value = next;
    persist();
  }

  async function send(id: number, text: string) {
    const t = text.trim();
    if (!t || sending.value) return;
    conversations.value[id] = [...messagesFor(id).filter((m) => !m.hint), { role: "user", content: t }];
    persist();
    await complete(id);
  }

  /** Reset and re-ask the initial question for the active CVE. */
  async function restart() {
    const cve = activeCve.value;
    if (!cve) return;
    conversations.value[cve.id] = [{ role: "user", content: buildInitialMessage(cve, settings.state.privacyMode) }];
    persist();
    await complete(cve.id);
  }

  /** Called after a model/provider becomes available — kick off the staged first
   *  message if the conversation hasn't gotten a real answer yet. */
  async function ensureStarted() {
    const cve = activeCve.value;
    if (!cve || !model.value.trim() || sending.value) return;
    if (!hasRealReply(cve.id)) await restart();
  }

  function setProviderModel(p: Provider, m: string) {
    provider.value = p;
    model.value = m;
  }

  return {
    conversations,
    activeCve,
    sending,
    provider,
    model,
    messagesFor,
    open,
    close,
    clearHistory,
    send,
    restart,
    ensureStarted,
    setProviderModel,
  };
});
