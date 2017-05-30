module.exports = {
  extends: [
    "airbnb",
  ],
  parser: "babel-eslint",
  env: {
    browser: true,
    node: true,
  },
  ecmaFeatures: {
    jsx: true,
    es6: true,
  },
  settings: {
    'import/resolver': {
      webpack: {
        config: "webpack.shared.js"
      }
    }
  },
};