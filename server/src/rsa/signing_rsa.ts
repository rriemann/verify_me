import { asym } from "kbpgp";
import { assert, BigInteger, check, KeyManager } from "verifyme_utility";

/**
 * Signs the given blinded message.
 *
 * @param {string} message
 *    The message to sign.
 * @param {KeyManager} key_manager
 *    The {KeyManager} containing the ecc based key
 *    that will be used to sign the message.
 * @returns {string}
 *    The signed message.
 */
export default function sign(message: string, key_manager: KeyManager): string {

  assert(check.isString(message));
  assert(check.isKeyManagerForRsaSign(key_manager));

  const key_pair = key_manager.get_primary_keypair();
  const priv = key_pair.priv as asym.RSA.Priv;
  const pub = key_pair.pub as asym.RSA.Pub;

  const m = new BigInteger(message, 32);
  const n = pub.n;
  const d = priv.d;

  return m.modPow(d, n).toRadix(32);
}
