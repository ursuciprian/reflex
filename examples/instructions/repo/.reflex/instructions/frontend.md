---
when: the task changes or reviews front-end React components, styling or UI copy
paths: ["web/**/*.tsx", "web/**/*.css", "**/*.module.css"]
keywords: [tailwind, storybook]
---
- Components are function components with named exports; no default exports.
- Colours, spacing and type come from the `web/src/theme.ts` tokens; never hard-code hex values or px sizes.
- Every interactive element needs an accessible name and must work with the keyboard.
- UI copy is sentence case. Run `npm run lint:web` and `npm run test:web` before calling it done.
