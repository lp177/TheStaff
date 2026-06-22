import { createApp } from "vue";
import { createPinia } from "pinia";

// Vue Flow base styles (required) — imported once, here.
import "@vue-flow/core/dist/style.css";
import "@vue-flow/core/dist/theme-default.css";
import "@vue-flow/controls/dist/style.css";

import "./style.css";
import App from "./App.vue";
import { router } from "./router";

createApp(App).use(createPinia()).use(router).mount("#app");
