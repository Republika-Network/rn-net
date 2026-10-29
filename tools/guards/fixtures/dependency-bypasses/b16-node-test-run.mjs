import { run } from 'node:test';
const stream = run({ files: [new URL('../../../tools/x/evil.mjs', import.meta.url).pathname], isolation: 'none' });
for await (const _ of stream) { /* drain */ }
