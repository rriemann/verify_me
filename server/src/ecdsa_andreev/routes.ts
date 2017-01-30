import { Request, Response } from "express";
import { BigInteger } from "verifyme_utility";

import keys from "../keys";
import Signer from "./signing";

const secret_scalar = new Map<string, {p: BigInteger, q: BigInteger}>();

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
  response.render("index", { public_key: key.armored_pgp_public });
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

  const json: { px?: string, py?: string, qx?: string, qy?: string, error?: string } = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    const key = await keys.ecc_promise;
    const { p, P, q, Q } = await Signer.prepare(key);

    secret_scalar.set(request.body.hashed_token, {p, q});

    json.px = P.affineX.toRadix(32);
    json.py = P.affineY.toRadix(32);
    json.qx = Q.affineX.toRadix(32);
    json.qy = Q.affineY.toRadix(32);

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

  if (request.body.hasOwnProperty("hashed_token")) {

    const token = secret_scalar.get(request.body.hased_token);
    const blinded_message = request.body.message;

    if (token != null) {
      const key = await keys.ecc_promise;
      json.signed_blinded_message = Signer.sign(blinded_message, token, key);
    }
  }

  if (json.signed_blinded_message == null) {
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
