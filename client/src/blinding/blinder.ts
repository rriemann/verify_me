"use strict";

import { KeyManager } from "kbpgp";
import { BigInteger } from "verifyme_utility";

import BlindSignaturePacket from "../pgp/blind_signature_packet";
import BlindingContext from "./blinding_context";

/**
 * Representation of a blinding algorithm.
 */
abstract class Blinder<Context extends BlindingContext> {

  public context: Context;
  public key_manager: KeyManager;
  public token: BigInteger;

  /**
   * Blinding context initialization.
   * Could be possibly async so its not done by the constructor.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key.
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  public abstract initContext(key_manager: KeyManager, token: BigInteger): Promise<void>;

  /**
   * Blinds a given message.
   *
   * @param {BigInterger} message
   *    The message to blind.
   * @return {BigInteger}
   *    The blinded message.
   */
  public abstract blind(message: BigInteger): BigInteger;

  /**
   * Unblinds a given messsage.
   *
   * @param {BigInteger} message
   *    The blinded message.
   * @return {BigInteger}
   *    The unblinded message.
   */
  public abstract unblind(signed_blinded_message: BigInteger, original_message?: BigInteger): BigInteger;

  /**
   * Forges a blind signature.
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  public abstract forgeSignature(packet: BlindSignaturePacket): Promise<void>
}

export default Blinder;
