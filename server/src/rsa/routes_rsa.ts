import { Request, Response } from "express";

import keys from "../keys";
import sign from "./signing_rsa";

/**
 * Render a RSA key into index html.
 *
 * @param {Request} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {Response} response
 *    HTTP server response
 */
async function renderIndex(request: Request, response: Response): Promise<void> {
  const key = await keys.rsa_promise;
  response.render("index", {public_key: key.armored_pgp_public});
};

/**
 * Signs a given RSA blinded message.
 *
 * @param {Request} request
 *    Received HTTP request to access the handled route & method combination.
 * @param {Response} response
 *    HTTP server response
 */
async function signBlindedMessage(request: Request, response: Response): Promise<void> {

  const json: {signed_blinded_message?: string, error?: string } = {};

  if (request.hasOwnProperty("body") && request.body.hasOwnProperty("hashed_token")) {

    const key = await keys.rsa_promise;
    json.signed_blinded_message = sign(request.body.message, key);

  } else {

    json.error = "Missing Token...";
  }

  response.send(json);
};

const routes_rsa_api = {
  renderIndex,
  signBlindedMessage,
};

export default routes_rsa_api;
