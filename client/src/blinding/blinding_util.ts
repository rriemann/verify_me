"use strict";

import { assert, BigInteger, check, KeyManager } from "verifyme_utility";

import client from "../client";
import BlindSignaturePacket from "../pgp/blind_signature_packet";
import Blinder from "./blinder";
import BlindingContext from "./blinding_context";
import AndreevEcdsaBlinder from "./ecdsa_andreev/blinder";
import ButunEcdsaBlinder from "./ecdsa_butun/blinder";
import RsaBlinder from "./rsa/blinder_rsa";

/**
 * Creates a public key algorithm specific {Blinder} instance.
 *
 * @param {KeyManager} key_manager
 *    A public key to identify the target algorithm.
 * @param {BigInteger} token
 *    The server identifier token.
 * @param {{algorithm: string, implementation:string}} algorithm_hints
 *    Additional information to determine the requester Blinder.
 * @returns {Blinder}
 *    The new generated algorithm specific {Blinder}
 */
async function createBlinderForKeyManager(key_manager: KeyManager, token: BigInteger,
                                          algorithm: string): Promise<Blinder<BlindingContext>> {

  assert(check.isKeyManager(key_manager));
  assert(check.isBigInteger(token));
  assert(check.isString(algorithm));

  let blinder: Blinder<BlindingContext>;

  if (check.isKeyManagerForRsaSign(key_manager)) {

    blinder = new RsaBlinder();

  } else if (check.isKeyManagerForEcdsaSign(key_manager)) {

    if ("andreev" === algorithm) {
      blinder = new AndreevEcdsaBlinder();
    } else {
      blinder = new ButunEcdsaBlinder();
    }

  } else {

    const public_key_algorithm = key_manager.get_primary_keypair().get_type();
    throw new Error("Unsupported public key algorithm id: " + public_key_algorithm);
  }

  assert(null !== blinder);
  await blinder.initContext(key_manager, token);
  return blinder;
}

/**
 * Collects all available public information to create and initialize the
 * related {Blinder} instance and a {BlindSignaturePacket}.
 *
 * @returns {blinder: Blinder<BlindingContext>, packet: BlindSignaturePacket}
 */
async function prepareBlinding(): Promise<{blinder: Blinder<BlindingContext>,
                                           packet: BlindSignaturePacket}> {

  const public_key = await client.getPublicKey();
  const server_public_key = await client.getServerPublicKey();
  const token = client.getToken();
  const algorithm = client.getAlgorithmHints();

  const blinder = await createBlinderForKeyManager(server_public_key, token, algorithm);
  if (blinder.context === null) {
    throw new Error("Blinding context must not be null.");
  }

  const packet = new BlindSignaturePacket(public_key, server_public_key, blinder.context);
  return { blinder, packet };
}

const blinding_util_api = {
  createBlinderForKeyManager,
  prepareBlinding,
};

export default blinding_util_api;
