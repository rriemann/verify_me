"use strict";

import { BigInteger, Buffer, KeyManager, Tags } from "verifyme_utility";

/**
 * An abstract blinding context object.
 *
 * An algorithm specific full valid blinding context stores all
 * information that are necessary to complete the related blind
 * and unblinding steps.
 */
abstract class BlindingContext {

  /**
   * Checks if a given {object} is a BlindingContext which fulfills all requirements
   * to start the blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the blind signature creation
   *    else {false}
   */
  public static isValidBlindingContext(object: Object): boolean {
    return (object instanceof BlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The public key_manager that belongs to the blind signature issuer.
   * @return {BlindingContext}
   *    The generated blinding context.
   */
  public static fromKey(key_manager: KeyManager): BlindingContext {
    throw new Error("Implementation Mising");
  }

  public hashed_token: BigInteger;

  /**
   * Checks if all information are present that are necessary
   * to start the blind signature creation.
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  public abstract containsAllBlindingInformation(): boolean;

  /**
   * Encodes raw signature data to fit the pgp standard for signatures of
   * the used public key algorithm.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {function} hasher
   *    unused
   * @returns {BigInteger}
   *    the incoming signature data stored as {BigInteger}
   */
  public abstract encodeSignaturePayload(data: Buffer, hasher: Function): BigInteger;

  /**
   * Returns the id of the verification algorithm.
   *
   * @return {number}
   *    Id of the algorithm to verify a signature
   *    generated with this blinding context.
   */
  public verificationAlgorithm(): number {
    return Tags.verification_algorithms.default;
  }
}

export default BlindingContext;
