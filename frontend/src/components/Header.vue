<template>
    <div class="header">
        <brand></brand>
        <search></search>
        <nav-bar></nav-bar>
    </div>
</template>

<script>

import Brand from './Brand.vue'
import Search from './Search.vue'
import NavBar from './NavBar.vue'

export default {
    components: {
        Brand,
        Search,
        NavBar
    }
}
</script>

<style>
.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 20px;
    background-color: #42b983;
    color: white;
}

</style>