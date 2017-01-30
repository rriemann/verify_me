"use strict";

import { ecc } from "kbpgp";
import { assert, BigInteger, check, KeyManager, Point, util } from "verifyme_utility";

/// TODO
async function prepareBlinding(key_manager: KeyManager): Promise<{k: BigInteger, Ŕ: Point}> {

  assert(check.isKeyManager(key_manager));

  const public_key_package = key_manager.get_primary_keypair().pub as ecc.ECDSA.Pub;
  const curve = public_key_package.curve;
  const n = curve.n;
  const G = curve.G;

  let k = null;
  let Ŕ = null;
  let ŕ = null;

  do {

    k = await util.generateRandomScalar(curve);
    Ŕ = G.multiply(k);
    ŕ = Ŕ.affineX.mod(n);

  } while (ŕ.compareTo(BigInteger.ZERO) === 0);

  return {k, Ŕ};
}

/// TODO
function sign(message: string, k: BigInteger, key_manager: KeyManager) {

  assert(check.isString(message));
  assert(check.isKeyManagerForEcdsaSign(key_manager));
  assert(check.isBigInteger(k));

  const ḿ = new BigInteger(message, 32);

  const key_material = key_manager.get_primary_keypair();

  const pub = key_material.pub as ecc.ECDSA.Pub;
  const n = pub.curve.n;
  const G = pub.curve.G;

  const priv = key_material.priv as ecc.ECDSA.Priv;
  const d = priv.x;

  const Ŕ = G.multiply(k);
  const ŕ = Ŕ.affineX.mod(n);
  const dŕ = d.multiply(ŕ);
  const kḿ = k.multiply(ḿ);

  const ś = dŕ.add(kḿ).mod(n);

  return ś.toRadix(32);
}

const signing_ecdsa_api = {
  prepare: prepareBlinding,
  sign,
};

export default signing_ecdsa_api;
