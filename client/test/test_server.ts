"use strict";

import { assert } from "chai"
import * as sinon from "sinon"
import { BigInteger, check } from "verifyme_utility"

import RsaBlindingContext from "../src/blinding/rsa/blinding_context_rsa"
import server from "../src/server_requests"

describe("server", function() {

  let fake_server: sinon.SinonFakeServer;

  beforeEach(() => {
    fake_server = sinon.fakeServer.create();
    fake_server.autoRespond = true;
  });

  afterEach(() => {
    fake_server.restore();
  });

  ///---------------------------------
  /// #requestRsaBlinding()
  ///---------------------------------

  describe("#requestRsaBlinding()", () => {

    it("should return a promise", () => {
      const task = server
        .requestRsaBlinding(BigInteger.ZERO, new RsaBlindingContext())
        .catch(() => {});
      
      assert.instanceOf(task, Promise);
    });

    it("should reject when a network error occurred", () => {

      const context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      const request_promise = server.requestRsaBlinding(BigInteger.ZERO, context)
        .catch(error => assert.instanceOf(error, Error));

      assert.equal(1, fake_server.requests.length);
      //fake_server.requests[0].onload = null;
      //fake_server.requests[0];

      return request_promise;
    });

    it("should reject and return status text error if status is not 200", () => {

      const expected = {code: 404, status_text: new Error("Not Found")};
      fake_server.respondWith([expected.code, {"Content-Type": "text/plain"}, ""]);

      let context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      return server.requestRsaBlinding(BigInteger.ZERO, context)
        .catch((error:Error) => {error == expected.status_text});
    });

    it("should resolve and return server response if status is 200", () =>{

      const expected = "deadbeef";
      const answer = JSON.stringify({signed_blinded_message: expected});
      fake_server.respondWith([200, {"Content-Type": "text/plain"}, answer]);

      let context = new RsaBlindingContext();
      context.hashed_token = BigInteger.ZERO;

      return server.requestRsaBlinding(BigInteger.ZERO, context)
        .then(answer => assert.equal(expected, answer.toRadix(32)));
    });
  });
});