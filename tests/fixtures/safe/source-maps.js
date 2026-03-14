// Safe: source maps disabled in production config
module.exports = {
  mode: 'production',
  devtool: false,
  entry: './src/index.js',
  output: {
    filename: 'bundle.js',
    path: __dirname + '/dist',
  },
};
