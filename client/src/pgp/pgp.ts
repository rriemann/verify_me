import * as kbpgp from "kbpgp";
const Constants = (kbpgp as any).const;

import { armor, opkts, util } from "kbpgp";
import { assert, Buffer, check, KeyManager } from "verifyme_utility";

import BlindSignaturePacket from "./blind_signature_packet";

/**
 * Exports the given public key (stored in a {KeyManager}) as binary data
 * and injects a given key signature packet directly behind the related userid.
 *
 * This is necessary because kbpgp does not support non self-signature signature
 * packets.
 *
 * @param {KeyManager} key_manager
 *    The public key to export.
 * @param {Signature} signature_packet
 *    The key signature to inject.
 * @param {object} opts
 *    Possibility to add additional options to pass
 *    to the kbpgp key export function.
 * @returns {Buffer}
 *    The public pgp key with additional injected signature
 *    as binary data.
 */
function exportKeyToBinaryAndInjectSignature(key_manager: KeyManager,
                                             signature_packet: opkts.Signature,
                                             opts = { subkey: false }): Buffer {
  assert(check.isKeyManager(key_manager));
  assert(check.isObject(opts));
  assert(signature_packet !== null);

  const pgp_engine = key_manager.pgp;
  const primary_userid = key_manager.get_userids_mark_primary()[0];
  const export_packets = [pgp_engine.key(pgp_engine.primary).export_framed(opts)];

  pgp_engine.userids.reduce((packets, userid) => {

    packets.push(userid.write(), userid.get_framed_signature_output());
    if (primary_userid === userid) {
      packets.push(signature_packet.replay());
    }

    return packets;

  }, export_packets);

  opts.subkey = true;

  pgp_engine.subkeys.reduce((packets, subkey) => {

    const material = pgp_engine.key(subkey);
    packets.push(
      material.export_framed(opts),
      material.get_subkey_binding_signature_output(),
    );

    return packets;

  }, export_packets);

  util.assert_no_nulls(export_packets);
  return Buffer.concat(export_packets);
}

/**
 * Exports the input public key with an ascii armor and injects the signature packet.
 *
 * This is necessary because kbpgp does not support non self-signature signature
 * packets.
 *
 * @param {KeyManager} key_manager
 *    The public key_manager to export.
 * @param {Signature} signature_packet
 *    The key_manager signature to inject.
 * @returns {string}
 *    Ascii armored version of the input public key including the
 *    injected signature packet.
 */
function exportKeyToAsciiWithSignature(key_manager: KeyManager,
                                       signature_packet: opkts.Signature): Promise<string> {
  assert(check.isKeyManager(key_manager), "No Key Manager");

  const user_id_packet = [key_manager.get_userids_mark_primary()[0]];

  return new Promise((resolve, reject) => {

    signature_packet.verify(
      user_id_packet,
      (err) => {

        if (err) {
          return reject(err);
        }

        const key_binary = this.exportKeyToBinaryAndInjectSignature(key_manager, signature_packet);
        const key_ascii = armor.encode(Constants.openpgp.message_types.public_key, key_binary);
        return resolve(key_ascii);
      },
    );
  });
}

const pgp_api = {
  exportKeyToBinaryAndInjectSignature,
  exportKeyToAsciiWithSignature,
};

export default pgp_api;
