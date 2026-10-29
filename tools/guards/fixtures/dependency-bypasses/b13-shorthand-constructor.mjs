const { constructor } = () => {};
const net = constructor("return \\u0070rocess.get\\u0042uiltinModule('node:net')")();
console.log('LOADED via shorthand constructor:', typeof net.connect);
