import { symlinkSync, rmSync } from 'node:fs';
const link = new URL('./gen-link.mjs', import.meta.url);
rmSync(link, { force: true });
symlinkSync(new URL('../../../tools/x/evil.mjs', import.meta.url).pathname, link);
const { c } = await import('./gen-link.mjs');
console.log('LOADED via runtime symlink:', typeof c);
rmSync(link, { force: true });
