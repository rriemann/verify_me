"use strict";

import { KeyManager } from "kbpgp"

import client from"../client"
import BlindSignaturePacket from "../pgp/blind_signature_packet"
import EcdsaBlinder from "./ecdsa/blinder_ecdsa"
import RsaBlinder from "./rsa/blinder_rsa"
import util, { assert } from "verifyme_utility"

/**
 * Creates a public key algorithm specific {Blinder} instance.
 *
 * @param {KeyManager} key_manager
 *    A public key to identify the target algorithm.
 * @param {BigInteger} token
 *    The server identifier token.
 * @returns {Blinder}
 *    The new generated algorithm specific {Blinder}
 */
async function createBlinderForKeyManager(key_manager, token)
{
  assert(util.isKeyManager(key_manager));
  assert(util.isBigInteger(token));

  let blinder = null;

  if (util.isKeyManagerForRsaSign(key_manager)) {

    blinder = new RsaBlinder();

  } else if (util.isKeyManagerForEcdsaSign(key_manager)) {

    blinder = new EcdsaBlinder();

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
 * @returns {{blinder: Blinder, packet: BlindSignaturePacket}}
 */
async function prepareBlinding()
{
  const public_key = await client.getPublicKey();
  const server_public_key = await client.getServerPublicKey();
  const token = client.getToken();

  const blinder = await createBlinderForKeyManager(server_public_key, token);
  const packet = new BlindSignaturePacket(public_key, server_public_key, blinder.context);

  return { blinder, packet };
}

const blinding_util_api = {
  createBlinderForKeyManager,
  prepareBlinding
};

export default blinding_util_api;