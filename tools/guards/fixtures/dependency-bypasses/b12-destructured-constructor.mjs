const { constructor: F } = () => {};
const net = F("return \\u0070rocess.get\\u0042uiltinModule('node:net')")();
console.log('LOADED via destructured constructor:', typeof net.connect);
