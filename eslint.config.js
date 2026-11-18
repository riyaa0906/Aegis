import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['**/dist/**', '**/.venv/**', 'apps/agent/**', 'apps/classifier/**'] },
  ...tseslint.configs.recommended,
)
