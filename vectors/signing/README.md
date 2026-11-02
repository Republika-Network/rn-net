# Signing known-answer vectors (RN-NET-03B2-B1)

`known-answers.json` collects **public** vectors from four sources. The JavaScript toolchain (`tools/signing.test.mjs`) and the independent Python reference (`tools/reference/rnnet_tx_reference.py`) must both reproduce them.

| Source | Pinned at | License | What is used |
|---|---|---|---|
| [EIP-155](https://eips.ethereum.org/EIPS/eip-155) | the EIP text | CC0-1.0 | The example signing data, hash, key (`0x46` × 32), r, s, v and sender |
| [ethers.js](https://github.com/ethers-io/ethers.js) `testcases/transactions.json.gz` | `9c1e82e1230526ebcd62902890c4f24b1f7f7d79` | MIT, Copyright (c) 2016-2025 Richard Moore | Three EIP-1559 (London) cases: fields, unsigned and signed bytes, signature |
| [ethereum/tests](https://github.com/ethereum/tests) `TransactionTests/ttEIP1559` | `ff69b74f2eb44fbe1bf09627f06ebf69cc72ea67` | MIT, Copyright 2014-2025 Ethereum Foundation | Two transactions refused for leading zeros |
| [ripple-binary-codec](https://github.com/XRPLF/xrpl.js/tree/main/packages/ripple-binary-codec) tests | `c61c9bc768b02ccecfab8c382036d3c93cbcd57c` | ISC, Copyright (c) 2015 Ripple Labs Inc. | Field headers, native amounts, a signing blob, two addresses and a transaction hash |

**Notes on the vectors:**
- **ethers private keys are not copied.** The `sender` of each ethers case was derived from its published private key by the pure-Python secp256k1 and Keccak code of the reference, and the key itself was not copied. The JavaScript toolchain recovers the same sender from the signature.
- **The XRPL signing blob** is a `Payment`, which the Genesis codec refuses. The tests therefore rebuild it from the codec's primitives (field headers, length prefixes, amounts, account IDs), plus the two `Payment` field codes given in the vector.

Every key in these vectors is public. None may be used for anything but tests.

**Permission notices.** The ISC and MIT licenses above permit copying with their notices, which are reproduced here:

- *ripple-binary-codec:* Permission to use, copy, modify, and distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies. THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- *ethers.js (MIT), Copyright (c) 2016-2025 Richard Moore; Copyright 2014-2025 Ethereum Foundation:* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
- *ethereum/tests (MIT), Copyright 2014-2025 Ethereum Foundation:* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**Coverage gap.** No official vector here is an Ed25519-signed XRPL transaction. The signing-blob vector is the preimage of a `Payment`, and the hash vector is a secp256k1-signed transaction. So the XRPL Ed25519 / `STX\0` path rests on:
- the official field and prefix vectors;
- RFC 8032 Ed25519 (the Node built-in, and the Python reference);
- the two RN-NET implementations agreeing.

Adding an official Ed25519 XRPL signed-transaction vector is a follow-up.
