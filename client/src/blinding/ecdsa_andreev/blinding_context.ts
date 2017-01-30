"use strict";

import { ecc } from "kbpgp";
import { assert, BigInteger, Buffer, check, Curve, KeyManager } from "verifyme_utility";

import BlindingContext from "../blinding_context";

/**
 * A ecc blinding context.
 */
export default class AndreevEcdsaBlindingContext extends BlindingContext {

  /**
   * Checks if a given {object} is a AndreevEcdsaBlindingContext which fulfills all requirements
   * to start the ecdsa_andreev blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the ecdsa_andreev blind signature creation
   *    else {false}
   */
  public static isValidBlindingContext(object: Object): boolean {
    return (object instanceof AndreevEcdsaBlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the ECC based input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The ECC based public key_manager that belongs to the blind signature issuer.
   * @return {AndreevEcdsaBlindingContext}
   *    The generated blinding context.
   */
  public static fromKey(key_manager: KeyManager): AndreevEcdsaBlindingContext {
    assert(check.isKeyManagerForEcdsaSign(key_manager));

    const public_key_package = key_manager.get_primary_keypair().pub;

    const context = new AndreevEcdsaBlindingContext();
    context.curve = ( public_key_package as ecc.ECDSA.Pub).curve;

    return context;
  }

  public blinding_factor: {
    a: BigInteger,
    b: BigInteger,
    c: BigInteger,
    d: BigInteger,
  };

  public curve: Curve;
  public hashed_token: BigInteger;

  constructor() {
    super();
  }

  /**
   * Checks if all information are present that are necessary
   * to start the ECDSA based blind signature creation.
   *
   * For our RSA based blind signatures we need:
   *
   *  - {Curve} signers curve
   *  - {BigInteger} hash of the given token to authenticate our request
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  public containsAllBlindingInformation(): boolean {
    if (null === this.curve) {
      return false;
    }

    return check.isCurve(this.curve)
        && check.isBigInteger(this.hashed_token)
        && null != this.blinding_factor
        && this.blinding_factor.hasOwnProperty("a") && check.isBigInteger(this.blinding_factor.a)
        && this.blinding_factor.hasOwnProperty("b") && check.isBigInteger(this.blinding_factor.b)
        && this.blinding_factor.hasOwnProperty("c") && check.isBigInteger(this.blinding_factor.c)
        && this.blinding_factor.hasOwnProperty("d") && check.isBigInteger(this.blinding_factor.d);
  }

  /**
   * ECDSA signature do not need any further encoding.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {function} hasher
   *    unused
   * @returns {BigInteger}
   *    the incoming signature data stored as {BigInteger}
   */
  public encodeSignaturePayload(data: Buffer, hasher?: Function): BigInteger {
    assert(check.isBuffer(data));
    return BigInteger.fromBuffer(data);
  }
}
