module.exports = {
  extends: [
    'plugin:vue/essential',
    'eslint:recommended'
  ],
  parser: 'vue-eslint-parser',
  parserOptions: {
    parser: 'babel-eslint',
    ecmaVersion: 2018,
    sourceType: 'module'
  },
  plugins: [
    'vue'
  ],
  env: {
    browser: true,
    node: true,
    es6: true
  },
  rules: {
    'vue/multi-word-component-names': 'off' // Disable the rule globally
  }
};