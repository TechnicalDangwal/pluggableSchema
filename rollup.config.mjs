import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';

/** @type {import('rollup').RollupOptions[]} */
export default [
  // JS Bundles (CJS + ESM)
  {
    input: 'src/index.ts',
    output: [
      { file: 'dist/index.cjs', format: 'cjs', exports: 'named' },
      { file: 'dist/index.mjs', format: 'esm' }
    ],
    external: ['mongoose', 'bcrypt', 'jsonwebtoken', 'crypto'],
    plugins: [resolve(), commonjs(), typescript({ tsconfig: './tsconfig.json' })]
  },

  // Type Definitions
  {
    input: 'src/index.ts',
    output: [{ file: 'dist/index.d.ts', format: 'es' }],
    plugins: [dts()],
  }
];


