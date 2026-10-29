export default /`/;
const g = Reflect.get(process, 'getBuilt' + 'inModule');
const f = (0, eval);
console.log('LOADED', typeof g('node:net').connect, f('1'));
// `
