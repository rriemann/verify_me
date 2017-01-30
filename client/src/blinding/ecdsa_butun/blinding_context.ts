"use strict";

import { assert, BigInteger, check, Curve, KeyManager, Point, Tags } from "verifyme_utility";

import BlindingContext from "../blinding_context";

/**
 * A ecc blinding context.
 */
export default class ButunEcdsaBlindingContext extends BlindingContext {

  /**
   * Checks if a given {object} is a ButunEcdsaBlindingContext which fulfills all requirements
   * to start the ecdsa_andreev blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the ecdsa blind signature creation
   *    else {false}
   */
  public static isValidBlindingContext(object: any): boolean {
    return (object instanceof ButunEcdsaBlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the ECC based input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The ECC based public key_manager that belongs to the blind signature issuer.
   * @return {ButunEcdsaBlindingContext}
   *    The generated blinding context.
   */
  public static fromKey(key_manager: KeyManager): ButunEcdsaBlindingContext {
    assert(check.isKeyManagerForEcdsaSign(key_manager));

    const public_key_package: any = key_manager.get_primary_keypair().pub;

    const context = new ButunEcdsaBlindingContext();
    context.curve = public_key_package.curve;
    context.signers_public_key = public_key_package.R;

    return context;
  }

  public blinding_factor: {
    a: BigInteger,
    b: BigInteger,
  };

  public curve: Curve;
  public signers_public_key: Point;

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
    if (this.curve === null || this.signers_public_key === null) {
      return false;
    }

    return check.isCurve(this.curve)
        && check.isBigInteger(this.hashed_token)
        && check.isPoint(this.signers_public_key)
        && this.curve.isOnCurve(this.signers_public_key)
        && null != this.blinding_factor
        && this.blinding_factor.hasOwnProperty("a") && check.isBigInteger(this.blinding_factor.a)
        && this.blinding_factor.hasOwnProperty("b") && check.isBigInteger(this.blinding_factor.b);
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
  public encodeSignaturePayload(data: Buffer, hasher: Function): BigInteger {
    assert(check.isBuffer(data));
    return BigInteger.fromBuffer(data);
  }

  /**
   * Returns the id of the verification algorithm.
   *
   * @return {number}
   *    Id of the butun algorithm to verify a signature
   *    generated with this blinding context.
   */
  public verificationAlgorithm(): number {
    return Tags.verification_algorithms.butun;
  }
}
