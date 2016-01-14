"use strict";

import keys from "../keys"
import Signer from "./signing_ecdsa"

let secret_scalar = {};

/// TODO
function render_key(request, response)
{
  response.render("index", {public_key: keys.ecc_key.armored_pgp_public})
}

/// TODO
async function init_blinding(request, response)
{
  let json = {};
  if (request.body.hasOwnProperty("hashed_token")) {

    const { p, P, q, Q } = await Signer.prepare(keys.ecc_key);

    secret_scalar[request.body.hashed_token] = {p, q};

    json.px = P.affineX.toRadix(32);
    json.py = P.affineY.toRadix(32);
    json.qx = Q.affineX.toRadix(32);
    json.qy = Q.affineY.toRadix(32);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json)
}

/// TODO
function sign_blinded_message(request, response)
{
  let json = {};
  if (request.body.hasOwnProperty("hashed_token")) {

    const secret_scalars = secret_scalar[request.body.hashed_token];
    const blinded_message = request.body.message;

    json.signed_blinded_message = Signer.sign(blinded_message, secret_scalars, keys.ecc_key);

  } else {
    json.error = "Missing Token...";
  }

  response.send(json);
}

const routes_ecdsa_api = {
  render_key,
  init_blinding,
  sign_blinded_message
};

export default routes_ecdsa_api;