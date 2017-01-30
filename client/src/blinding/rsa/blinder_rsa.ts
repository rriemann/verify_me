"use strict";

import { assert, BigInteger, check, KeyManager, util } from "verifyme_utility";

import BlindSignaturePacket from "../../pgp/blind_signature_packet";
import server from "../../server_requests";
import Blinder from "../blinder";
import RsaBlindingContext from "./blinding_context_rsa";

/**
 * Representation of the rsa blinding algorithm.
 *
 * The variable naming follows the algorithms notation.
 */
export default class RsaBlinder extends Blinder<RsaBlindingContext> {

  constructor() {
    super();
  }

  /**
   * Initializes the internal {RsaBlindingContext}.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key.
   *    which is necessary to extract the public exponent and
   *    the modulus length.
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  public async initContext(key_manager: KeyManager, token: BigInteger): Promise<void> {
    assert(check.isKeyManagerForRsaSign(key_manager));
    assert(check.isBigInteger(token));

    const context = RsaBlindingContext.fromKey(key_manager);
    if (context.modulus === null) {
      throw new Error("Modulus must not be null.");
    }

    const blinding_factor = await util.generateRsaBlindingFactor(context.modulus.bitLength());
    context.blinding_factor = token.multiply(blinding_factor);
    context.hashed_token = util.calculateSha512(token);

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;
  }

  /**
   * Blinds the given message.
   *
   *    message * blinding_factor^(-1) (mod N)
   *    message * (r ^ ( blinding_fact
   *
   * @param {BigInteger} message
   *    The original message.
   *
   * @returns {BigInteger}
   *    The blinded message.
   */
  public blind(message: BigInteger): BigInteger {
    assert(check.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    if (this.context === null) {
      throw new Error("Context must not be null.");
    }

    const rsa_context = this.context as RsaBlindingContext;
    const r = rsa_context.blinding_factor;
    const e = rsa_context.public_exponent;
    const N = rsa_context.modulus;

    if (r === null || e === null || N === null) {
      throw new Error("r, e, N must not be null.");
    }

    return message.multiply(r.modPow(e, N));
  }

  /**
   * Unblinds the given message.
   *
   *    message * blinding_factor^(-1) (mod N)
   *
   * @param {BigInteger} message
   *    The blinded message.
   *
   * @returns {BigInteger}
   *    The unblinded message.
   */
  public unblind(message: BigInteger): BigInteger {
    assert(check.isBigInteger(message));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    const rsa_context = this.context as RsaBlindingContext;
    const N = rsa_context.modulus;
    const r = rsa_context.blinding_factor;

    if (r === null || N === null) {
      throw new Error("r, N must not be null.");
    }

    const r_inv = r.modInverse(N);
    return message.multiply(r_inv).mod(N);
  }

  /**
   * Forges a rsa based blind signature.
   *
   * To achieve this the prepared raw signature is blinded and send to the server.
   * The server signs the blinded message and the result is send back.
   * Afterwards the result is unblinded and inject into the given signature packet.
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  public async forgeSignature(packet: BlindSignaturePacket): Promise<void> {
    assert(packet instanceof BlindSignaturePacket);
    assert(check.isBigInteger(packet.raw_signature));
    assert(RsaBlindingContext.isValidBlindingContext(this.context));

    if (this.context === null) {
      throw new Error("Context must not be null.");
    }

    const message = packet.raw_signature;
    const blinded_message = this.blind(message);
    const signed_blinded_message = await server.requestRsaBlinding(blinded_message, this.context);

    if (signed_blinded_message instanceof Error) {
      throw signed_blinded_message;
    }

    const signed_message = this.unblind(signed_blinded_message);
    packet.sig = signed_message.to_mpi_buffer();
    packet.raw = packet.write_unframed();
  }
}
