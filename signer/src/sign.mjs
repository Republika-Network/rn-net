// The offline signer (ADR-RN-017; ADR-RN-016 §3 to §5).
//
// It signs only an intent that passes its checks and whose digest equals the approved one, with
// a key bound to the intent's network and purpose whose address is the intent's sender. It
// verifies its own output before returning it. It has no key generation, no key loader, no file
// access and no network; in RN-NET-03B2-B1 it is called only with label-derived test keys.
import { createHash } from 'node:crypto';
import {
  approvedIntent,
  encodeEip1559Signed,
  encodeEip1559Unsigned,
  encodeXrplTx,
  IntentNetwork,
  intentSender,
  intentSequence,
  TxError,
  TxErrorCode,
  xrplSigningPreimage,
} from '../../packages/tx-intent/src/index.mjs';
import { ed25519Sign, keccak256, secp256k1SignDigest } from './crypto.mjs';
import { bindKey } from './keys.mjs';
import { transactionHash, verifySignedTransaction } from './verify.mjs';

/**
 * A signer with an in-memory sign log keyed on (key address, Sequence or nonce). B1 knows no
 * resolution of a signed transaction, so every signed sequence number stays unresolved: signing
 * the same intent again is RNTX_ALREADY_SIGNED, and signing any other intent with that key is
 * RNTX_SEQUENCE_UNRESOLVED. The persistent log and same-nonce replacement are later milestones.
 */
export function createSigner() {
  const log = new Map(); // address -> { sequence, intentDigest }
  const sign = (intent, approvedDigest, key) => {
    const checked = approvedIntent(intent, approvedDigest);
    const bound = bindKey(key);
    if (bound.network !== checked.network) throw new TxError(TxErrorCode.KEY_NETWORK_MISMATCH, `key is for ${bound.network}`);
    if (bound.purpose !== checked.purpose) throw new TxError(TxErrorCode.KEY_PURPOSE_MISMATCH, `key is for ${bound.purpose}`);
    if (intentSender(checked) !== bound.address) throw new TxError(TxErrorCode.SENDER_MISMATCH, 'the intent sender is not the key address');
    const tx = checked.transaction;
    if (checked.network === IntentNetwork.XRPL_TESTNET && tx.SigningPubKey !== bound.publicKey) throw new TxError(TxErrorCode.SENDER_MISMATCH, 'SigningPubKey is not the key');
    const previous = log.get(bound.address);
    if (previous) {
      throw new TxError(previous.intentDigest === approvedDigest ? TxErrorCode.ALREADY_SIGNED : TxErrorCode.SEQUENCE_UNRESOLVED, `sequence ${previous.sequence} already signed with this key`);
    }
    let bytes;
    if (checked.network === IntentNetwork.XRPL_TESTNET) {
      const signature = ed25519Sign(bound.secretKey, xrplSigningPreimage(tx));
      bytes = encodeXrplTx({ ...tx, TxnSignature: signature.toString('hex').toUpperCase() });
    } else {
      const signature = secp256k1SignDigest(bound.secretKey, keccak256(encodeEip1559Unsigned(tx)));
      bytes = encodeEip1559Signed(tx, signature);
    }
    const signedTransaction = checked.network === IntentNetwork.XRPL_TESTNET ? bytes.toString('hex').toUpperCase() : `0x${bytes.toString('hex')}`;
    const verification = verifySignedTransaction({ intent: checked, approvedDigest, signedTransaction });
    if (verification.outcome !== 'PASS') throw new TxError(verification.code, 'the signed bytes failed self-verification');
    log.set(bound.address, { sequence: intentSequence(checked), intentDigest: approvedDigest });
    return Object.freeze({
      network: checked.network,
      intentDigest: approvedDigest,
      signedTransaction,
      blobSha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      transactionHash: transactionHash(checked.network, bytes),
      verification: Object.freeze(verification),
    });
  };
  return Object.freeze({ sign });
}
