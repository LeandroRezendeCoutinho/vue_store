# Vuejs 2

```
src/
├── components/
│   ├── ui/                  # Reusable UI components
│   │   ├── BaseButton.vue
│   │   ├── BaseInput.vue
│   │   ├── BaseModal.vue
│   │   └── BaseCard.vue
│   ├── layout/              # Layout components
│   │   ├── AppHeader.vue
│   │   ├── AppFooter.vue
│   │   ├── AppSidebar.vue
│   │   └── AppLayout.vue
│   ├── common/              # Common utilities components
│   │   ├── AppLoader.vue
│   │   ├── AppError.vue
│   │   └── AppNotification.vue
│   └── features/            # Feature-specific components
│       ├── auth/
│       │   ├── LoginForm.vue
│       │   └── RegisterForm.vue
│       ├── dashboard/
│       │   ├── DashboardStats.vue
│       │   └── DashboardChart.vue
│       └── products/
│           ├── ProductCard.vue
│           ├── ProductList.vue
│           └── ProductFilter.vue
├── views/                   # Page-level components
│   ├── HomePage.vue
│   ├── AboutPage.vue
│   ├── auth/
│   │   ├── LoginPage.vue
│   │   └── RegisterPage.vue
│   ├── dashboard/
│   │   ├── DashboardPage.vue
│   │   └── ProfilePage.vue
│   └── products/
│       ├── ProductListPage.vue
│       ├── ProductDetailPage.vue
│       └── ProductCreatePage.vue
├── store/                   # Vuex store
│   ├── index.js            # Main store file
│   ├── modules/            # Vuex modules
│   │   ├── auth.js
│   │   ├── products.js
│   │   └── ui.js
│   └── types.js            # Mutation/action types
├── router/                  # Vue Router
│   └── index.js
├── utils/                   # Utility functions
│   ├── helpers.js
│   ├── constants.js
│   └── validators.js
├── mixins/                  # Vue mixins
│   ├── formMixin.js
│   ├── apiMixin.js
│   └── validationMixin.js
├── directives/              # Custom directives
│   ├── clickOutside.js
│   └── focus.js
├── plugins/                 # Vue plugins
│   └── axios.js
└── assets/                  # Static assets
    ├── styles/
    │   ├── main.scss
    │   └── variables.scss
    ├── images/
    └── icons/
```

## Vue CLI Configuration (vue.config.js)
```javascript
const path = require('path')

module.exports = {
  configureWebpack: {
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
        '@components': path.resolve(__dirname, 'src/components'),
        '@views': path.resolve(__dirname, 'src/views'),
        '@store': path.resolve(__dirname, 'src/store'),
        '@utils': path.resolve(__dirname, 'src/utils'),
        '@assets': path.resolve(__dirname, 'src/assets'),
        '@mixins': path.resolve(__dirname, 'src/mixins')
      }
    }
  }
}
```

## Vuex Store Structure
```javascript
// store/index.js
import Vue from 'vue'
import Vuex from 'vuex'
import auth from './modules/auth'
import products from './modules/products'
import ui from './modules/ui'

Vue.use(Vuex)

export default new Vuex.Store({
  modules: {
    auth,
    products,
    ui
  }
})
```

```javascript
// store/modules/auth.js
export default {
  state: {
    user: null,
    isAuthenticated: false
  },
  mutations: {
    SET_USER(state, user) {
      state.user = user
      state.isAuthenticated = !!user
    }
  },
  actions: {
    login({ commit }, credentials) {
      // Login logic
    }
  },
  getters: {
    currentUser: state => state.user,
    isAuthenticated: state => state.isAuthenticated
  }
}
```

## Router Configuration
```javascript
// router/index.js
import Vue from 'vue'
import Router from 'vue-router'
import HomePage from '@/views/HomePage.vue'
import LoginPage from '@/views/auth/LoginPage.vue'

Vue.use(Router)

export default new Router({
  mode: 'history',
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomePage
    },
    {
      path: '/login',
      name: 'login',
      component: LoginPage
    }
    // ... other routes
  ]
})
```

## Main.js Configuration
```javascript
// main.js
import Vue from 'vue'
import App from './App.vue'
import router from './router'
import store from './store'
import './registerServiceWorker'

// Global components registration (optional)
import BaseButton from '@/components/ui/BaseButton.vue'
import BaseInput from '@/components/ui/BaseInput.vue'

Vue.component('BaseButton', BaseButton)
Vue.component('BaseInput', BaseInput)

Vue.config.productionTip = false

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')
```

## Auto-registration of Components
```javascript
// components/index.js
import Vue from 'vue'

// UI components
import BaseButton from './ui/BaseButton.vue'
import BaseInput from './ui/BaseInput.vue'

// Layout components
import AppHeader from './layout/AppHeader.vue'
import AppFooter from './layout/AppFooter.vue'

const components = {
  BaseButton,
  BaseInput,
  AppHeader,
  AppFooter
}

Object.entries(components).forEach(([name, component]) => {
  Vue.component(name, component)
})

export default components
```

```javascript
// main.js
import '@/components'
```

## UI Component
``` html
<!-- components/ui/BaseButton.vue -->
<template>
  <button :class="['base-button', variant]" @click="$emit('click')">
    <slot></slot>
  </button>
</template>

<script>
export default {
  name: 'BaseButton',
  props: {
    variant: {
      type: String,
      default: 'primary',
      validator: value => ['primary', 'secondary', 'danger'].includes(value)
    }
  }
}
</script>

<style scoped>
.base-button {
  padding: 8px 16px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.primary {
  background-color: #42b883;
  color: white;
}

.secondary {
  background-color: #f0f0f0;
  color: #333;
}
</style>
```

## Page Component
``` html
<!-- views/HomePage.vue -->
<template>
  <AppLayout>
    <div class="home-page">
      <h1>Welcome to Vue 2 App</h1>
      <BaseButton @click="handleClick">Click me</BaseButton>
      <ProductList :products="products" />
    </div>
  </AppLayout>
</template>

<script>
import AppLayout from '@/components/layout/AppLayout.vue'
import BaseButton from '@/components/ui/BaseButton.vue'
import ProductList from '@/components/features/products/ProductList.vue'

export default {
  name: 'HomePage',
  components: {
    AppLayout,
    BaseButton,
    ProductList
  },
  data() {
    return {
      products: [] // Would typically come from Vuex
    }
  },
  methods: {
    handleClick() {
      this.$store.dispatch('someAction')
    }
  }
}
</script>
```
