<template>
    <div class="brand">
        <img src="../assets/logo.png" alt="Logo" class="logo"/>
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
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
}

.logo {
    width: 75px;
    height: 75px;
    margin-bottom: -24px;
}

.brand-name {
    font-size: 1.5em;
    font-weight: bold;
}

</style>
