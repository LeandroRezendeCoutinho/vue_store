<template>
  <div id="app">
    <AppLoader v-if="isLoading" />
    <AppNotification
      v-if="notification.show"
      :message="notification.message"
      :type="notification.type"
    />
    <main>
      <router-view />
    </main>
  </div>
</template>

<script>
import AppLoader from "./components/AppLoader.vue";
import AppNotification from "./components/AppNotification.vue";

export default {
  name: "App",
  data: () => ({
    isLoading: false,
    notification: {
      show: false,
      message: "",
      type: "",
    },
  }),
  components: {
    AppLoader: AppLoader,
    AppNotification: AppNotification,
  },
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
