import { defineStore } from "pinia";
import { computed, reactive, watch } from "vue";
import type { AiModel } from "@/lib/api";

export type Provider = "anthropic" | "openai";
export const PROVIDERS: Provider[] = ["anthropic", "openai"];
export const PROVIDER_LABEL: Record<Provider, string> = {
  anthropic: "Claude (Anthropic)",
  openai: "OpenAI",
};

const LS_KEY = "thestaff_ai_settings_v1";

interface Persisted {
  keys: Record<Provider, string>;
  models: Record<Provider, AiModel[]>;
  selectedModel: Record<Provider, string>;
  defaultProvider: Provider;
  privacyMode: boolean;
}

function blank(): Persisted {
  return {
    keys: { anthropic: "", openai: "" },
    models: { anthropic: [], openai: [] },
    selectedModel: { anthropic: "", openai: "" },
    defaultProvider: "anthropic",
    privacyMode: false,
  };
}

function load(): Persisted {
  const base = blank();
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return base;
    const p = JSON.parse(raw) as Partial<Persisted>;
    return {
      keys: { ...base.keys, ...(p.keys ?? {}) },
      models: { ...base.models, ...(p.models ?? {}) },
      selectedModel: { ...base.selectedModel, ...(p.selectedModel ?? {}) },
      defaultProvider: p.defaultProvider === "openai" ? "openai" : "anthropic",
      privacyMode: typeof p.privacyMode === "boolean" ? p.privacyMode : false,
    };
  } catch {
    return base;
  }
}

export const useSettingsStore = defineStore("settings", () => {
  const state = reactive<Persisted>(load());

  watch(
    state,
    () => {
      try {
        localStorage.setItem(LS_KEY, JSON.stringify(state));
      } catch {
        /* localStorage may be unavailable */
      }
    },
    { deep: true },
  );

  const hasKey = (p: Provider) => state.keys[p].trim().length > 0;
  const anyKey = computed(() => PROVIDERS.some(hasKey));
  const configuredProviders = computed(() => PROVIDERS.filter(hasKey));

  // The provider used by default for a new chat: the chosen default if it has a
  // key, otherwise the first provider that does.
  const activeProvider = computed<Provider | null>(() => {
    if (hasKey(state.defaultProvider)) return state.defaultProvider;
    return configuredProviders.value[0] ?? null;
  });

  function modelFor(p: Provider): string {
    return state.selectedModel[p] || state.models[p][0]?.id || "";
  }

  const activeModel = computed(() =>
    activeProvider.value ? modelFor(activeProvider.value) : "",
  );

  function setKey(p: Provider, v: string) {
    state.keys[p] = v;
    if (!v.trim()) {
      state.models[p] = [];
      state.selectedModel[p] = "";
    }
  }
  function setDefaultProvider(p: Provider) {
    state.defaultProvider = p;
  }
  function setModel(p: Provider, id: string) {
    state.selectedModel[p] = id;
  }
  function setModels(p: Provider, list: AiModel[]) {
    state.models[p] = list;
    if (list.length && !list.some((m) => m.id === state.selectedModel[p])) {
      state.selectedModel[p] = list[0].id;
    }
  }

  return {
    state,
    PROVIDER_LABEL,
    hasKey,
    anyKey,
    configuredProviders,
    activeProvider,
    activeModel,
    modelFor,
    setKey,
    setDefaultProvider,
    setModel,
    setModels,
  };
});
