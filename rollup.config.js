import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import sourceMaps from 'rollup-plugin-sourcemaps';
import json from 'rollup-plugin-json';
import babel from 'rollup-plugin-babel';

const pkg = require('./package.json');

export default {
  input: 'src/main.js',
  output: [
    {
      file: pkg.main,
      name: 'StandardFileJs', // Global variable name on the browser
      format: 'umd',
      sourcemap: true
    },
    { file: pkg.module, format: 'es', sourcemap: true }
  ],
  // Indicate here external modules you don't wanna include in your bundle (i.e.: 'lodash')
  external: [],
  watch: {
    include: 'src/**'
  },
  plugins: [
    // Allow json resolution
    json(),
    // Allow bundling cjs modules (unlike webpack, rollup doesn't understand cjs)
    commonjs(),
    // Allow node_modules resolution, so you can use 'external' to control
    // which external modules to include in the bundle
    // https://github.com/rollup/rollup-plugin-node-resolve#usage
    resolve(),
    // Transpile to es5
    babel({
      runtimeHelpers: true,
      exclude: 'node_modules/**'
    }),
    // Resolve source maps to the original source
    sourceMaps()
  ]
};
