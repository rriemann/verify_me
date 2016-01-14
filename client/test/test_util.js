"use strict";

import { assert } from "chai"
import { Buffer, ecc } from "kbpgp"

import client from"../src/client"
import util from "../src/util"

import { controls } from "./helper/client_control"
import keys, { public_keys } from "./helper/keys"

describe("util", function() {

  ///---------------------------------
  /// #assert()
  ///---------------------------------

  describe("#assert", () => {

    it("nothing should happen when condition validates to true", () => {
      util.assert(true);
    });

    it("should throw if condition validates to false", () => {
      assert.throws(() => util.assert(false));
    });

    it("should throw with custom message if condition validates to false", () => {
      const custom_message = "custom message";
      assert.throws(() => util.assert(false, custom_message), custom_message);
    });
  });

  ///---------------------------------
  /// #generateKeyFromString()
  ///---------------------------------

  describe("#generateKeyFromString", () => {

    it("should throw if input is not a string", () => {
      return util.generateKeyFromString(123)
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should throw if input string is not an ascii armored key", () => {
      return util.generateKeyFromString("a broken key")
        .catch(error => assert.instanceOf(error, Error));
    });

    for (const id in public_keys) {
      it("Setting: " + id +" - should return the promise of a {KeyManager} object if input is a pgp key", () => {
        const promise = util.generateKeyFromString(public_keys[id]);
        assert.instanceOf(promise, Promise);

        return promise
          .then(key => assert.isTrue(util.isKeyManager(key)));
      });
    }
  });

  ///---------------------------------
  /// #generateTwoPrimeNumbers()
  ///---------------------------------

  describe("#generateTwoPrimeNumbers", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return util.generateTwoPrimeNumbers(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return util.generateTwoPrimeNumbers(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 128", () => {
      return util.generateTwoPrimeNumbers(127)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 128"));
    });

    it("should return a rejected Promise if input bit size is bigger than 8192", () => {
      return util.generateTwoPrimeNumbers(8193)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 8192"));
    });

    it("should return two {BigInteger} prime numbers of given bit length", (done) => {
      const bitLength = 256;

      return util.generateTwoPrimeNumbers(bitLength)
        .then((primeNumbers) => {

          assert.equal(2, primeNumbers.length);

          primeNumbers.forEach((prime) => {
            assert.isTrue(util.isBigInteger(prime));
            assert.isTrue(prime.isProbablePrime());
            assert.equal(bitLength, prime.bitLength());
          });
          done();
        })
    });
  });

  ///---------------------------------
  /// #generateRsaBlindingFactor()
  ///---------------------------------

  describe("#generateRsaBlindingFactor", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return util.generateRsaBlindingFactor(null)
        .then(() => assert.fail())
        .catch((error) => assert.include(error.message, "no integer"));
    });

    it("should return a rejected Promise if input bit size is not multiple of 8", () => {
      return util.generateRsaBlindingFactor(15)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "multiple of 8"));
    });

    it("should return a rejected Promise if input bit size is smaller than 256", () => {
      return util.generateRsaBlindingFactor(255)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, ">= 256"));
    });

    it("should return a rejected Promise if input bit size is bigger than 16384", () => {
      return util.generateRsaBlindingFactor(16385)
        .then((answer) => assert.fail())
        .catch((error) => assert.include(error.message, "<= 16384"));
    });

    it("should return a {BigInteger} numbers of given bit length", (done) => {
      const bitLength = 256;

      return util.generateRsaBlindingFactor(bitLength)
        .then((blinding_factor) => {

          assert.isTrue(util.isBigInteger(blinding_factor));
          assert.equal(bitLength, blinding_factor.bitLength());

          done();
        })
    });
  });

  ///---------------------------------
  /// #hashMessageSha512()
  ///---------------------------------

  describe("#hashMessageSha512()", () => {

    it("should throw if input parameter is no string", () => {
      assert.throws(() => util.hashMessageSha512(123));
    });

    it("should return a hash digest with bit length 512", () => {
      const expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

      const result = util.hashMessageSha512("abc");

      assert.isTrue(util.isBigInteger(result));
      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });

  ///---------------------------------
  /// #isBigInteger()
  ///---------------------------------

  describe("#isBigInteger()", () => {

    it("should return false when parameter is a no {BigInteger}", () => {
      assert.isFalse(util.isBigInteger(123));
    });

    it ("should return true when input parameter is a valid {BigInteger}", () => {
      assert.isTrue(util.isBigInteger(util.BigInteger.ZERO));
    });
  });

  ///---------------------------------
  /// #isBuffer()
  ///---------------------------------

  describe("#isBuffer()", () => {

    it("should return false when parameter is a no {Buffer}", () => {
      assert.isFalse(util.isBuffer(123));
    });

    it ("should return true when input parameter is a valid {Buffer}", () => {
      assert.isTrue(util.isBuffer(new Buffer(123)));
    });
  });

  ///---------------------------------
  /// #isCurve()
  ///---------------------------------

  describe("#isCurve()", () => {

    it("should return false when parameter is a no {Curve}", () => {
      assert.isFalse(util.isCurve(123));
    });

    it ("should return true when input parameter is a valid {Curve}", () => {
      assert.isTrue(util.isCurve(ecc.curves.brainpool_p512()));
    });
  });

  ///---------------------------------
  /// #isFunction()
  ///---------------------------------

  describe("#isFunction()", () => {

    it ("should return false when input parameter is not a valid {function}", () => {
      assert.isFalse(util.isFunction(123));
    });

    it ("should return true when input parameter is a valid {function}", () => {
      assert.isTrue(util.isFunction(() => {}));
    });
  });

  ///---------------------------------
  /// #isInteger()
  ///---------------------------------

  describe("#isInteger()", () => {

    it ("should return false when input parameter is not a valid integer {number}", () => {
      assert.isFalse(util.isInteger("123"));
    });

    it ("should return true when input parameter is a valid integer {number}", () => {
      assert.isTrue(util.isInteger(123));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(util.isKeyManager({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(public_keys[0]);
      assert.isTrue(util.isKeyManager(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManagerForEcdsaSign()
  ///---------------------------------

  describe("#isKeyManagerForEcdsaSign()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(util.isKeyManagerForEcdsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(keys.ecc.bp[512].pub);
      assert.isTrue(util.isKeyManagerForEcdsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isKeyManager()
  ///---------------------------------

  describe("#isKeyManager()", () => {

    it("should return false when parameter is not a {KeyManager}", () => {
      assert.isFalse(util.isKeyManagerForRsaSign({}));
    });

    it("should return true when parameter is a {KeyManager}", async () => {
      const key_manager = await util.generateKeyFromString(keys.rsa[1024].pub);
      assert.isTrue(util.isKeyManagerForRsaSign(key_manager));
    });
  });

  ///---------------------------------
  /// #isObject()
  ///---------------------------------

  describe("#isObject()", () => {

    it("should return false when parameter is not an {object}", () => {
      assert.isFalse(util.isObject(123));
    });

    it("should return true when parameter is an {object}", () => {
      assert.isTrue(util.isObject({}));
    });
  });

  ///---------------------------------
  /// #isPoint()
  ///---------------------------------

  describe("#isPoint()", () => {

    it("should return false when parameter is not a {Point}", () => {
      assert.isFalse(util.isPoint(123));
    });

    it("should return true when parameter is a {Point}", () => {
      assert.isTrue(util.isPoint(ecc.curves.brainpool_p512().G));
    });
  });

  ///---------------------------------
  /// #isString()
  ///---------------------------------

  describe("#isString()", () => {

    it("should return false when parameter is not a {string}", () => {
      assert.isFalse(util.isString(123));
    });

    it("should return true when parameter is a {string}", () => {
      assert.isTrue(util.isString("123"));
    });
  });
});
