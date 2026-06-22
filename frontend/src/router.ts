import { createRouter, createWebHistory } from "vue-router";
import ConsentPage from "@/views/ConsentPage.vue";
import Dashboard from "@/views/Dashboard.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "consent", component: ConsentPage },
    { path: "/dashboard", name: "dashboard", component: Dashboard },
    { path: "/:pathMatch(.*)*", redirect: "/" },
  ],
});
