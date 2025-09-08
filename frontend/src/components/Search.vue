<template>
    <div class="search">
        <input type="text" placeholder="Search..." />
        <button>Search</button>
    </div>
</template>


<script>
export default {

}
</script>

<style>
.search {
    display: flex;
    align-items: center;
}

.search input {
    padding: 8px;
    border: 1px solid #ccc;
    border-radius: 4px;
    margin-right: 10px;
}

.search button {
    padding: 8px 12px;
    background-color: #42b983;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

.search button:hover {
    background-color: #369e6b;
}
</style>