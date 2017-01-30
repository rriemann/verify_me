import { Request, Response } from "express";
import { BigInteger } from "verifyme_utility";

import keys from "../keys";
import Signer from "./signing";

const secret_scalar = new Map<string, BigInteger>();

/**
 * Render an ECC key into index html.
 *
 * @param {Request} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {Response} response
 *    HTTP server response
 */
async function renderIndex(request: Request, response: Response): Promise<void> {
  const key = await keys.ecc_promise;
  response.render("index", {public_key: key.armored_pgp_public});
}

/**
 * Initializes the ECDSA blind signature algorithm.
 *
 * @param {Request} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {Response} response
 *    HTTP server response
 */
async function initBlindingAlgorithm(request: Request, response: Response): Promise<void> {

  const json: {Ŕx?: string, Ŕy?: string, error?: string} = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    const key = await keys.ecc_promise;
    const { k, Ŕ } = await Signer.prepare(key);

    secret_scalar.set(request.body.hashed_token, k);

    json.Ŕx = Ŕ.affineX.toRadix(32);
    json.Ŕy = Ŕ.affineY.toRadix(32);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

/**
 * Signs a a given ECDSA blinded message.
 *
 * @param {Request} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {Response} response
 *    HTTP server response
 */
async function signBlindedMessage(request: Request, response: Response): Promise<void> {

  const json: {signed_blinded_message?: string, error?: string} = {};
  let request_scalar: BigInteger | undefined;

  if (request.body.hasOwnProperty("hashed_token") && secret_scalar.has(request.body.hashed_token)) {
    request_scalar = secret_scalar.get(request.body.hashed_token);

    if (request_scalar != null) {
      const blinded_message = request.body.message;
      const key = await keys.ecc_promise;

      json.signed_blinded_message = Signer.sign(blinded_message, request_scalar, key);
    }

  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

const routes_ecdsa_api = {
  renderIndex,
  initBlindingAlgorithm,
  signBlindedMessage,
};

export default routes_ecdsa_api;
