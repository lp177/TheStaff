<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink } from "vue-router";
import { api } from "@/lib/api";

const info = ref<{
  mode: "wifi" | "http";
  organizer: string;
  organizer_email: string;
  ssid: string;
  event: string;
  target_cidr: string;
  opt_in_count: number;
} | null>(null);

// "wifi": consent is established by possessing the WiFi password (out-of-band);
// the page is informational and headless/IoT devices need not visit it.
// "http": per-device explicit opt-in via the checkbox below.
const wifiMode = computed(() => (info.value?.mode ?? "wifi") !== "http");

const agreed = ref(false);
const joined = ref(false);
const submitting = ref(false);
const error = ref<string | null>(null);

onMounted(async () => {
  try {
    info.value = await api.consentInfo();
  } catch {
    /* show generic copy if status unavailable */
  }
});

async function join() {
  if (!wifiMode.value && !agreed.value) return; // http mode requires the checkbox
  submitting.value = true;
  error.value = null;
  try {
    await api.recordConsent(true);
    joined.value = true;
  } catch {
    error.value =
      "Couldn't record your opt-in — please check your connection and try again.";
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="wrap scroller">
    <div class="card">
      <div class="hero">
        <img class="logo" src="/logo.png" alt="" width="44" height="44" />
        <h1>Security challenge</h1>
      </div>

      <p v-if="wifiMode" class="lede">
        This is an <strong>opt-in security-awareness challenge</strong> run by
        <strong>{{ info?.organizer || "the event team" }}</strong> at
        <strong>{{ info?.event || "this event" }}</strong>.
        <strong>Connecting any device to this WiFi means you agree it may be actively
        scanned</strong> as part of the game — including phones, laptops, and
        <strong>headless / IoT devices that can't show this page</strong> — so we can help
        you spot and fix weak spots together.
      </p>
      <p v-else class="lede">
        This is an <strong>opt-in security-awareness challenge</strong> run by
        <strong>{{ info?.organizer || "the event team" }}</strong> at
        <strong>{{ info?.event || "this event" }}</strong>. By joining, you agree that
        devices you connect to this network may be actively scanned as part of the game —
        so we can help you spot and fix weak spots together.
      </p>

      <div v-if="!joined">
        <h3>What we do</h3>
        <ul>
          <li>We perform <strong>network port scanning and version detection</strong> to look
            for open ports, outdated software, and common misconfigurations.</li>
          <li>We will <strong>not</strong> exploit, break into, alter, or take down your device,
            and we will <strong>not</strong> read your files or private traffic. It's detection only.</li>
        </ul>

        <div v-if="wifiMode" class="iot-note">
          📟 <strong>Got an IoT or headless device?</strong> (smart plug, camera, printer,
          TV…) Just connect it to <span class="mono">{{ info?.ssid || "the WiFi" }}</span> —
          there's nothing to click. By giving it the WiFi password you're consenting on its
          behalf, and it'll appear on the team's map automatically.
        </div>

        <h3>Scope</h3>
        <ul>
          <li><strong>In scope:</strong> devices you connect to
            <span class="mono">{{ info?.ssid || "the challenge WiFi" }}</span>
            (network <span class="mono">{{ info?.target_cidr || "the event LAN" }}</span>),
            for the duration of the event.</li>
          <li><strong>Out of scope:</strong> your personal accounts, the content of your traffic,
            and any device not on this network.</li>
        </ul>

        <h3>Your data</h3>
        <ul>
          <li>We collect: IP, MAC/vendor, open ports, service banners, and likely findings.</li>
          <li>It's kept only until the event ends, then deleted. Legal basis: your explicit opt-in.</li>
        </ul>

        <h3>How to opt out</h3>
        <ul>
          <li>Simply don't connect, or disconnect from
            <span class="mono">{{ info?.ssid || "the WiFi" }}</span> at any time.</li>
          <li>To have your data removed during the event, contact
            <a :href="`mailto:${info?.organizer_email || ''}`">{{ info?.organizer_email || "an organizer" }}</a>.</li>
        </ul>

        <label v-if="!wifiMode" class="consent">
          <input type="checkbox" v-model="agreed" />
          <span>I have read the above and consent to my connected device(s) being scanned for this challenge.</span>
        </label>
        <p v-else class="consent-note">
          You're already enrolled by being on this network. Tap below to see your results —
          or just go find a member of the {{ info?.organizer || "event" }} team.
        </p>

        <div class="actions">
          <button class="btn-primary" :disabled="(!wifiMode && !agreed) || submitting" @click="join">
            {{ submitting ? "…" : wifiMode ? "Show my results" : "Join the challenge" }}
          </button>
          <RouterLink class="ghost" to="/dashboard">
            {{ wifiMode ? "Open the live map" : "Connect without joining" }}
          </RouterLink>
        </div>
        <p v-if="error" class="error" role="alert">{{ error }}</p>
      </div>

      <div v-else class="thanks">
        <h2>You're in — thank you! 🎉</h2>
        <p>
          Find a member of the <strong>{{ info?.organizer || "event" }}</strong> team. Together
          you'll walk through anything we spot on your device and how to fix it. Every finding
          you fix turns <span class="state-solved">green</span>; anything you knowingly accept
          turns <span class="state-accepted">blue</span>.
        </p>
        <p class="muted">You can disconnect at any time to leave the challenge.</p>
        <RouterLink class="ghost" to="/dashboard">Open the live map →</RouterLink>
      </div>

      <footer>
        Authorized, consent-based security-awareness use only. See the project README and
        <code>documentation/ETHICS.md</code> for the rules of engagement.
        <span v-if="info"> · {{ info.opt_in_count }} participants opted in.</span>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.wrap { min-height: 100%; display: grid; place-items: start center; padding: 2.2rem 1rem; overflow: auto; }
.card { width: min(720px, 100%); background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 1.6rem 1.8rem; }
.hero { display: flex; align-items: center; gap: 0.7rem; }
.logo { width: 2.75rem; height: 2.75rem; display: block; }
h1 { margin: 0; font-size: 1.6rem; }
.lede { font-size: 1rem; line-height: 1.6; color: var(--text); }
h3 { margin: 1.2rem 0 0.3rem; font-size: 0.95rem; color: var(--brand); }
ul { margin: 0.2rem 0; padding-left: 1.2rem; line-height: 1.6; font-size: 0.92rem; }
.mono { font-family: ui-monospace, monospace; color: var(--text); }
.iot-note { margin: 1rem 0; padding: 0.8rem 0.95rem; background: color-mix(in srgb, var(--brand) 12%, var(--panel-2)); border: 1px solid color-mix(in srgb, var(--brand) 40%, transparent); border-radius: 10px; font-size: 0.9rem; line-height: 1.55; }
.consent-note { margin: 1.4rem 0 1rem; padding: 0.9rem; background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; font-size: 0.92rem; line-height: 1.5; }
.consent { display: flex; gap: 0.6rem; align-items: flex-start; margin: 1.4rem 0 1rem; padding: 0.9rem; background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; font-size: 0.92rem; line-height: 1.5; }
.consent input { margin-top: 0.2rem; width: 1.1rem; height: 1.1rem; }
.actions { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.ghost { font-size: 0.9rem; }
.error { color: var(--open); margin-top: 0.6rem; font-size: 0.88rem; }
.thanks h2 { margin-top: 0.5rem; }
.thanks p { line-height: 1.6; }
footer { margin-top: 1.6rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.76rem; color: var(--muted); line-height: 1.5; }
footer code { font-family: ui-monospace, monospace; }
</style>
