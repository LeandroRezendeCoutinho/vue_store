<template>
    <div class="brand">
        <img src="../assets/logo.png" alt="Logo" class="logo" width="50" height="50"/>
        <span class="brand-name"><slot>Vue store</slot></span>
    </div>
</template>

<script>
export default {

}
</script>

<style>
.brand {
    display: flex;
    align-items: center;
}
.logo {
    margin-right: 10px;
}
.brand-name {
    font-size: 1.5em;
    font-weight: bold;
}

</style>