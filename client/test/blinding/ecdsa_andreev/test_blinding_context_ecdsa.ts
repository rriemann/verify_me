"use strict";

import { assert } from "chai"
import { KeyManager } from "kbpgp"
import { BigInteger, Buffer, check, util } from "verifyme_utility"

import AndreevEcdsaBlindingContext from "../../../src/blinding/ecdsa_andreev/blinding_context"
import sample_keys from "./../../helper/keys"

describe("blinding_context_ecdsa", function() {

  //
  // suite functions
  //

  let context: AndreevEcdsaBlindingContext;
  let key_manager: KeyManager;

  before(async () => {
    key_manager = await util.generateKeyFromString(sample_keys.ecc.bp[256].pub);
  });

  beforeEach( () => {
    context = AndreevEcdsaBlindingContext.fromKey(key_manager);
    context.hashed_token = BigInteger.ONE;
    context.blinding_factor = {
      a: BigInteger.ONE,
      b: BigInteger.ONE,
      c: BigInteger.ONE,
      d: BigInteger.ONE
    }
  });

  ///-----------------------------------
  /// #isValidBlindingContext()
  ///-----------------------------------

  describe("#isValidBlindingContext", () => {

    it ("should return false after creation", () => {
      const local_context = new AndreevEcdsaBlindingContext();
      assert.isFalse(AndreevEcdsaBlindingContext.isValidBlindingContext(local_context));
    });

    it ("should return false if the hashed token is missing", () => {
      const local_context = new AndreevEcdsaBlindingContext();
      local_context.blinding_factor = {
        a: BigInteger.ONE,
        b: BigInteger.ONE,
        c: BigInteger.ONE,
        d: BigInteger.ONE
      }
      assert.isFalse(AndreevEcdsaBlindingContext.isValidBlindingContext(local_context));
    });

    it ("should return false if the blinding factors are missing", () => {
      const local_context = new AndreevEcdsaBlindingContext();
      local_context.hashed_token = BigInteger.ONE;
      assert.isFalse(AndreevEcdsaBlindingContext.isValidBlindingContext(local_context));
    });

    it ("should return true if all necessary information are present", () => {
      assert.isTrue(AndreevEcdsaBlindingContext.isValidBlindingContext(context));
    });
  });

  ///-----------------------------------
  /// #fromKey()
  ///-----------------------------------

  describe("#fromKey", () => {

    it ("should throw if input is not a valid ECDSA {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
      assert.throws(() => AndreevEcdsaBlindingContext.fromKey(key_manager));
    });

    it ("should return a context object if input is a valid ECDSA {KeyManager}", () => {
      const context = AndreevEcdsaBlindingContext.fromKey(key_manager);
      assert.instanceOf(context, AndreevEcdsaBlindingContext);
    });
  });

  ///-----------------------------------
  /// #containsAllBlindingInformation()
  ///-----------------------------------

  describe("#containsAllBlindingInformation", () => {

    it ("should return false after creation", () => {
      const local_context = new AndreevEcdsaBlindingContext();
      assert.isFalse(local_context.containsAllBlindingInformation());
    });

    it ("should return false if the curve is missing", () => {
      const local_context = new AndreevEcdsaBlindingContext();
      local_context.hashed_token = BigInteger.ONE;
      local_context.blinding_factor = {
        a: BigInteger.ONE,
        b: BigInteger.ONE,
        c: BigInteger.ONE,
        d: BigInteger.ONE
      }
      assert.isFalse(local_context.containsAllBlindingInformation());
    });

    it ("should return false if the hashed token is missing", () => {
      const local_context = AndreevEcdsaBlindingContext.fromKey(key_manager);
      local_context.blinding_factor = {
        a: BigInteger.ONE,
        b: BigInteger.ONE,
        c: BigInteger.ONE,
        d: BigInteger.ONE
      }
      assert.isFalse(local_context.containsAllBlindingInformation());
    });

    it ("should return false if the blinding factors are missing", () => {
      const local_context = AndreevEcdsaBlindingContext.fromKey(key_manager);
      local_context.hashed_token = BigInteger.ONE;
      assert.isFalse(local_context.containsAllBlindingInformation());
    });

    it ("should return true if all necessary information are present", () => {
      assert.isTrue(context.containsAllBlindingInformation());
    });
  });

  ///-----------------------------------
  /// #encodeSignaturePayload()
  ///-----------------------------------

  describe("#encodeSignaturePayload", () => {

    it ("should return the given Buffer as {BigInteger}", () => {
      const buffer = new Buffer([1, 2, 3]);
      const result = context.encodeSignaturePayload(buffer);

      assert.isTrue(check.isBigInteger(result));
      assert.isTrue(buffer.equals(result.toBuffer()));
    });
  });
});