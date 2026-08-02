// @ts-check

import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.next/**',
      '**/generated/**',
    ],
  },

  js.configs.recommended,

  ...tseslint.configs.recommended,

  {
    files: ['apps/api/**/*.ts'],

    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },

    rules: {
      '@typescript-eslint/no-explicit-any': 'error',

      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
    },
  },

  eslintConfigPrettier,
);
