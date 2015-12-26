"use strict";

import { assert } from "chai"

import * as client from "../src/client"
import * as util from "../src/util"

import { controls } from "./helper/helper"

describe("util", function() {

  describe("#bigInt2Bytes()", () => {

    let tests = [
      {arg: 1111, expected: "\u0004W"},
      {arg: 256,  expected: "\u0001\u0000"},
      {arg: 1,  expected: "\u0001"},
      {arg: 0,  expected: "\u0000"},
      {arg: "",  expected: "\u0000"},
      {arg: -1,  expected: "ÿ"},
      {arg: -2,  expected: "þ"},
      {arg: -256,  expected: "ÿ\u0000"},
      {arg: -1111,  expected: "û©"}
    ];

    tests.forEach((test) => {
      it("should return the byte string '" + test.expected + "' when input is BigInt with '" + test.arg + "'", () => {

        const bigInt = new util.BigInteger(test.arg.toString());
        const result = util.bigInt2Bytes(bigInt);
        assert.equal(test.expected, result);
      });
    });

    tests = [
      {arg: "123", expected: null},
      {arg: 123,   expected: null},
      {arg: true,  expected: null},
      {arg: {},    expected: null},
      {arg: null,    expected: null},
      {arg: undefined, expected: null}
    ];

    tests.forEach((test) => {
      it("should return 'null' when parameter is a " + typeof test.arg, () => {
        const result = util.bigInt2Bytes(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#bytes2hex", () => {

    const tests = [
      {arg: null, expected: ""},
      {arg: "\u0000", expected: "00"},
      {arg: "\u000f", expected: "0f"},
      {arg: "\u0010", expected: "10"},
      {arg: "a", expected: "61"},
      {arg: "a\u0001", expected: "6101"}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when input is '" + escape(test.arg) + "'", () => {
        assert.equal(test.expected, util.bytes2hex(test.arg));
      });
    });
  });

  describe("#hex2bytes", () => {

    const tests = [
      {arg: null, expected: ""},
      {arg: "00", expected: "\u0000"},
      {arg: "0f", expected: "\u000f"},
      {arg: "10", expected: "\u0010"},
      {arg: "61", expected: "a"},
      {arg: "6101", expected: "a\u0001"}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when input is '" + escape(test.arg) + "'", () => {
        assert.equal(test.expected, util.hex2bytes(test.arg));
      });
    });
  });

  describe("#generateKeyFromString", () => {

    it("should return null if input is not a string", () => {
      assert.isNull(util.generateKeyFromString(123));
    });

    it("should return null if input string is not an ascii armored key", () => {
      assert.isNull(util.generateKeyFromString("a broken key"));
    });

    it("should return a {Key} object if input is a valid ascii armored key", () => {
      const keyString =
        ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
          'Version: GnuPG v2',
          '',
          'mI0EVmmWTQEEALumEkoJ2JTwSJ+U+aUrKmpAu0B6Rm5FKLagRC6sRrU/2RU12jBi',
          'q/c+SyJriC6Rfar73MXuaXmTOtkBfz6XkEV70FZVdavciZhEBIYzBvJDOuP4cyXA',
          'vwFa+pfn1myoW67JNHANkiSM5KJQXtOuvCtofH07lG5WiH2MuLGLImtDABEBAAG0',
          'G0pvaG4gRG9lIDxqb2huLmRvZUBmb28uY29tPoi3BBMBCAAhBQJWaZZNAhsDBQsJ',
          'CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEGs7P8KYU1e8x9gEAI+1rRdNtBCLou1R',
          'twaBDv/mMkmFfhcDqSk5TzK451cnOSI5YIm5IQFISjTdJm49v4h7UVJB0wNM4QKX',
          'bioX1e0AyOXTfqMHCfgZMpkbbMMvI4MBjp+hvQ/qByu3whsbVb0b4zJ1HPOoKc4o',
          'C/SCtSWGyTFV/YLRSBZEPEs/wyJnuI0EVmmWTQEEAL9VPU4uNMXgIGikhwkawDUw',
          'bgXWc/Cx/CSPbK+PXAGddTyrMWW9xrKvPrJfBiMq5kQlwD7IhCbmPu10h+brWZmj',
          'pXLxcWUWPnaWIXRR4f/lZSai6k7SZmTpKGXLLliO+Sna/uzBsgijAtOsK5EWEqj1',
          'FZzt1jSRApRarKcHgy6pABEBAAGInwQYAQgACQUCVmmWTQIbDAAKCRBrOz/CmFNX',
          'vAx9A/9A1atvnTlGj+lKh9VrlN5CZ4jZMMEsSy5iw311YNnAZhn4gMTMrbWrNyWI',
          '9PX2VpMxQHlT21l4OJgbof5gp7mOw0HdD0akMa0L3U4Ybd/JgloBDu9HUVB9mT0+',
          'CVKecnStCMounFvM2rc5uv9HcIgeLes4ccFJUzGSpeThYhyPEw==',
          '=w97z',
          '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

      const key = util.generateKeyFromString(keyString);
      assert.isNotNull(key);
      assert.isTrue(util.isOpenPGPKey(key));
    });
  });

  describe("#generateTwoPrimeNumbers", () => {

    it("should return a rejected Promise if input parameter is no integer", () => {
      return util.generateTwoPrimeNumbers(null)
        .then(() => assert.fail())
        .catch((error) => assert.typeOf(error, "string"));
    });

    it("should throw an error when sth. wents wrong", (done) => {
      return util.generateTwoPrimeNumbers(7)
        .then((answer) => done(answer))
        .catch((error) => {
          assert.typeOf(error, "string");
          done();
        });
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

  describe("#getTextAreaContent", () => {

    beforeEach(() => {
      controls.loadFixture("test/fixture/minimal.html");
    });

    it("should return null if input parameter is no string", () => {
      assert.isNull(util.getTextAreaContent(123));
    });

    it("should return null if input id does not exists", () => {
      assert.isNull(util.getTextAreaContent("myNonExistingID"));
    });

    it("should return a string with the textarea content if input id exists", () => {
      const string = "123";
      controls.userPublicKeyString = string;

      const result = util.getTextAreaContent(client.user_public_key_element_id);
      assert.isTrue(util.isString(result));
      assert.equal(string, result);
    });
  });

  describe("#hashMessage()", () => {

    it("should return null if input parameter is no string", () => {
      assert.isNull(util.hashMessage(123));
    });

    it("should return a hash digest with bit length 512", () => {
      const expected_hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

      const result = util.hashMessage("abc");
      assert.equal(512, result.bitLength());
      assert.equal(expected_hex, result.toString(16));
    });
  });

  describe("#int2BigInt()", () => {

    let tests = [
      {arg: "123"}, {arg: true}, {arg: {}}, {arg: null}, {arg: undefined}, {arg: 123.12}
    ];

    tests.forEach((test) => {
      it("should return 'null' when parameter is a " + typeof test.arg, () => {
        assert.equal(test.expected, util.int2BigInt(test.arg));
      });
    });

    it("should return a 'BigInteger' when parameter is an integer", () => {
      assert.instanceOf(util.int2BigInt(0), util.BigInteger);
    });

    tests = [
      {arg: 0},
      {arg: 1}, {arg: -1},
      {arg: util.BigInteger.ZERO.DV}, {arg: -util.BigInteger.ZERO.DV}
    ];

    tests.forEach((test) => {
      it("should return '" + test.arg + "' when parameter is " + test.arg, () => {
        assert.equal(test.arg, util.int2BigInt(test.arg));
      });
    });
  });

  describe("#isBigInteger()", () => {

    const tests = [
      {arg: "123", expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: util.BigInteger.ONE, expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", () => {
        const result = util.isBigInteger(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isInteger()", () => {

    const tests = [
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: "123", expected: false},
      {arg: 123,   expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", () => {
        const result = util.isInteger(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isKeyReadSuccessful()", () => {

    const tests = [
      {arg: null, expected: false},
      {arg: undefined, expected: false},
      {arg: [], expected: false},
      {arg: {}, expected: false},
      {arg: {"err": 1}, expected: false},
      {arg: {"err": 1, "keys": 1}, expected: false},
      {arg: {"keys": 1}, expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is " + test.arg, () => {
        const result = util.isKeyReadSuccessful(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isObject()", () => {

    const tests = [
      {arg: undefined, expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: "123", expected: false},
      {arg: {},    expected: true},
      {arg: [],    expected: true},
      {arg: () => {}, expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", () => {
        const result = util.isObject(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isOpenPGPKey()", () => {

    const keyString =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v2',
        '',
        'mI0EVmmWTQEEALumEkoJ2JTwSJ+U+aUrKmpAu0B6Rm5FKLagRC6sRrU/2RU12jBi',
        'q/c+SyJriC6Rfar73MXuaXmTOtkBfz6XkEV70FZVdavciZhEBIYzBvJDOuP4cyXA',
        'vwFa+pfn1myoW67JNHANkiSM5KJQXtOuvCtofH07lG5WiH2MuLGLImtDABEBAAG0',
        'G0pvaG4gRG9lIDxqb2huLmRvZUBmb28uY29tPoi3BBMBCAAhBQJWaZZNAhsDBQsJ',
        'CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEGs7P8KYU1e8x9gEAI+1rRdNtBCLou1R',
        'twaBDv/mMkmFfhcDqSk5TzK451cnOSI5YIm5IQFISjTdJm49v4h7UVJB0wNM4QKX',
        'bioX1e0AyOXTfqMHCfgZMpkbbMMvI4MBjp+hvQ/qByu3whsbVb0b4zJ1HPOoKc4o',
        'C/SCtSWGyTFV/YLRSBZEPEs/wyJnuI0EVmmWTQEEAL9VPU4uNMXgIGikhwkawDUw',
        'bgXWc/Cx/CSPbK+PXAGddTyrMWW9xrKvPrJfBiMq5kQlwD7IhCbmPu10h+brWZmj',
        'pXLxcWUWPnaWIXRR4f/lZSai6k7SZmTpKGXLLliO+Sna/uzBsgijAtOsK5EWEqj1',
        'FZzt1jSRApRarKcHgy6pABEBAAGInwQYAQgACQUCVmmWTQIbDAAKCRBrOz/CmFNX',
        'vAx9A/9A1atvnTlGj+lKh9VrlN5CZ4jZMMEsSy5iw311YNnAZhn4gMTMrbWrNyWI',
        '9PX2VpMxQHlT21l4OJgbof5gp7mOw0HdD0akMa0L3U4Ybd/JgloBDu9HUVB9mT0+',
        'CVKecnStCMounFvM2rc5uv9HcIgeLes4ccFJUzGSpeThYhyPEw==',
        '=w97z',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

    const tests = [
      {arg: undefined, expected: false},
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: "123", expected: false},
      {arg: {},    expected: false},
      {arg: [],    expected: false},
      {arg: util.generateKeyFromString(keyString), expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", () => {
        const result = util.isOpenPGPKey(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });

  describe("#isString()", () => {

    const tests = [
      {arg: 123,   expected: false},
      {arg: true,  expected: false},
      {arg: {},    expected: false},
      {arg: undefined, expected: false},
      {arg: "123", expected: true}
    ];

    tests.forEach((test) => {
      it("should return '" + test.expected + "' when parameter is a " + test.arg + " {" + typeof test.arg + "}", () => {
        const result = util.isString(test.arg);
        assert.equal(test.expected, result);
      });
    });
  });
});
