import { setEngine } from 'node:crypto';
setEngine('/usr/lib/x86_64-linux-gnu/engines-3/afalg.so');
console.log('native shared object loaded and initialised by setEngine');
