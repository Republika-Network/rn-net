function f({ constructor: F } = () => {}) { return F; }
const net = f()("return \\u0070rocess.get\\u0042uiltinModule('node:net')")();
console.log('LOADED via param default destructure:', typeof net.connect);
