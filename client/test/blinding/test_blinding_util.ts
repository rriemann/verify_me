"use strict";

import { assert } from "chai"
import { BigInteger, check, Tags, util } from "verifyme_utility"
import { KeyManager } from "kbpgp"
import { SinonFakeServer, fakeServer } from "sinon"

import blinding_util from "../../src/blinding/blinding_util"
import AndreevEcdsaBlinder from "../../src/blinding/ecdsa_andreev/blinder"
import ButunEcdsaBlinder from "../../src/blinding/ecdsa_butun/blinder"
import RsaBlinder from "../../src/blinding/rsa/blinder_rsa"

import sample_keys from "../helper/keys"

describe("blinding_util", function() {

  //
  // suite functions
  //

  let rsa_key_manager: KeyManager;
  let ecc_key_manager: KeyManager;
  let token: BigInteger;

  let fake_server: SinonFakeServer;

  beforeEach(async () => {
    rsa_key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
    ecc_key_manager = await util.generateKeyFromString(sample_keys.ecc.nist[256].pub);
    token = new BigInteger("3", 16);

    fake_server = fakeServer.create();
    fake_server.autoRespond = true;
  });

  afterEach(() => {
    fake_server.restore();
  });

  ///---------------------------------
  /// #createBlinderForKeyManager()
  ///---------------------------------

  describe("#createBlinderForKeyManager()", () => {

    it("should return a rejected promise if key algorithm is encryption only key", () => {
      rsa_key_manager.primary.key.type = Tags.public_key_algorithms.RSA_ENCRYPT_ONLY;

      return blinding_util.createBlinderForKeyManager(rsa_key_manager, token, "")
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a rejected promise if key algorithm is unknown", () => {
      rsa_key_manager.primary.key.type = -1;

      return blinding_util.createBlinderForKeyManager(rsa_key_manager, token, "")
        .catch(error => assert.instanceOf(error, Error));
    });

    it("should return a RsaBlinder if input is a rsa key", async () => {
      const blinder = await blinding_util.createBlinderForKeyManager(rsa_key_manager, token, "");
      assert.instanceOf(blinder, RsaBlinder);
    });

    it("should return an ButunEcdsaBlinder if input is a ecc key", async () => {
      const blinder = await blinding_util.createBlinderForKeyManager(ecc_key_manager, token, "");
      fake_server.respondWith([200, {"Content-Type": "text/plain"}, ""]);
      assert.instanceOf(blinder, ButunEcdsaBlinder);
    });

    it("should return an AndreevEcdsaBlinder if input is a ecc key with andreev hint", async () => {

      const blinder = await blinding_util.createBlinderForKeyManager(
        ecc_key_manager, token, "andreev"
      );

      assert.instanceOf(blinder, AndreevEcdsaBlinder);
    });
  });
});