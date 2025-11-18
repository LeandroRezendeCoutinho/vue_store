import Vue from "vue";
import VueRouter from "vue-router";

Vue.use(VueRouter);

// Module not found: Error: Can't resolve '../views/About.vue' 
const routes = [
  {
    path: "/",
    name: "Home",
    component: () => import("@/views/Home.vue"),
  },
  {
    path: "/about",
    name: "About",
    component: () => import("@/views/About.vue"),
  },
];

const router = new VueRouter({
  mode: "history",
  routes,
});

export default router;
