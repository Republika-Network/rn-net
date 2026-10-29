import { copyFileSync, rmSync } from 'node:fs';
const copy = new URL('./gen-copy.mjs', import.meta.url);
copyFileSync(new URL('../../../tools/x/evil.mjs', import.meta.url), copy);
const { c } = await import('./gen-copy.mjs');
console.log('LOADED via runtime copy:', typeof c);
rmSync(copy, { force: true });
