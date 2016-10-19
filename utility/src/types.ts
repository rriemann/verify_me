"use strict";

import * as kbpgp from "kbpgp";

export import BigInteger = kbpgp.bn.BigInteger;
export import Curve = kbpgp.ecc.curves.Curve;
export import Buffer = kbpgp.Buffer;
export import KeyManager = kbpgp.KeyManager;

export const Tags = {
  public_key_algorithms: (<any>kbpgp).const.openpgp.public_key_algorithms,
  verification_algorithms: (<any>kbpgp).const.openpgp.verification_algorithms
};

export { Point } from "keybase-ecurve";