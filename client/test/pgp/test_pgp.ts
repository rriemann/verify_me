"use strict";

import { assert } from "chai"
import { check, util } from "verifyme_utility"
import { KeyManager, opkts } from "kbpgp"

import BlindSignaturePacket from "../../src/pgp/blind_signature_packet"
import pgp from "../../src/pgp/pgp"

import sample_keys from "../helper/keys"

describe("pgp", function() {

  let key_manager: KeyManager;
  let signature_packet: opkts.Signature;

  before(async () => {
    key_manager = await util.generateKeyFromString(sample_keys.rsa[1024].pub);
  });

  beforeEach(async () => {
    signature_packet = key_manager.primary._pgp.get_psc().all[0].sig;
  });

  afterEach(() => {});

  ///-----------------------------------------------
  /// #exportKeyToBinaryAndInjectSignature()
  ///-----------------------------------------------

  describe("#exportKeyToBinaryAndInjectSignature()", () => {

    it("should return a {Buffer} containg the signature if input is valid", () => {
      const result = pgp.exportKeyToBinaryAndInjectSignature(key_manager, signature_packet);
      assert.isTrue(check.isBuffer(result));

      const userid = key_manager.get_userids_mark_primary()[0];
      const userid_buffer = userid.get_framed_signature_output();
      const userid_buffer_index = result.indexOf(userid_buffer);
      assert.isBelow(-1, userid_buffer_index);

      const signature_buffer = signature_packet.replay();
      const signature_buffer_index = result.indexOf(signature_buffer);
      assert.isBelow(-1, signature_buffer_index);

      const start = userid_buffer_index +  userid_buffer.length;
      const end = start + signature_buffer.length;
      const slice = result.slice(start, end);
      assert.isTrue(signature_buffer.equals(slice));
    });
  });

  ///-----------------------------------------------
  /// #exportKeyToAsciiWithSignature()
  ///-----------------------------------------------

  describe("#exportKeyToAsciiWithSignature()", () => {

    it("should return the promise of an ascii armored key {string} if input is valid", () => {
      const result = pgp.exportKeyToAsciiWithSignature(key_manager, signature_packet);
      assert.instanceOf(result, Promise);

      return result
        .then(key_ascii => util.generateKeyFromString(key_ascii))
        .then(key_manager => assert.isTrue(check.isKeyManager(key_manager)));
    });
  });
});