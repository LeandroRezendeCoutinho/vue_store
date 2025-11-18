<template>
  <div class="notification">
    <p>{{ message }}</p>
  </div>
</template>

<script>
export default {
  props: {
    message: {
      type: String,
      required: true
    }
  }
}
</script>

<style>
.notification {
  border: 1px solid #42b983;
  background-color: #f9f9f9;
  padding: 12px 16px;
  border-radius: 4px;
  margin: 12px 0;
}
</style>

