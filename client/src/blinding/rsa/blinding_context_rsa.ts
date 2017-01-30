import { bn, hash, util } from "kbpgp";
import { assert, BigInteger, check, KeyManager } from "verifyme_utility";
import BlindingContext from "../blinding_context";

/** A rsa based blinding context. */
export default class RsaBlindingContext extends BlindingContext {

  /**
   * Checks if a given {object} is a RsaBlindingContext which fulfills all requirements
   * to start the rsa blind signature creation.
   *
   * @param {*} object
   *
   * @returns {boolean}
   *    {true} if the object can be used to start the rsa blind signature creation
   *    else {false}
   */
  public static isValidBlindingContext(object: any): boolean {
    return (object instanceof RsaBlindingContext) && object.containsAllBlindingInformation();
  }

  /**
   * Generates a blinding context based on the public information
   * extracted from the RSA based input {KeyManager} object.
   *
   * @param {KeyManager} key_manager
   *    The ECC based public key_manager that belongs to the blind signature issuer.
   * @return {RsaBlindingContext}
   *    The generated blinding context.
   */
  public static fromKey(key_manager: KeyManager): RsaBlindingContext {
    assert(check.isKeyManagerForRsaSign(key_manager));

    const public_key_package: any = key_manager.get_primary_keypair().pub;

    const blinding_context = new RsaBlindingContext();
    blinding_context.modulus = public_key_package.n;
    blinding_context.public_exponent = public_key_package.e;

    return blinding_context;
  }

  public blinding_factor: BigInteger;
  public modulus: BigInteger;
  public public_exponent: BigInteger;

  constructor() {
    super();
  }

  /**
   * Checks if all information are present that are necessary
   * to start the RSA based blind signature creation.
   *
   * For our RSA based blind signatures we need:
   *
   *  - {BigInteger} signers modulus
   *  - {BigInteger} signers public exponent
   *  - {BigInteger} the secret blinded factor
   *  - {BigInteger} hash of the given token to authenticate our request
   *
   * @returns {boolean}
   *    {true} if all necessary information are stored
   *    else {false}
   */
  public containsAllBlindingInformation(): boolean {
    return check.isBigInteger(this.modulus)
        && check.isBigInteger(this.public_exponent)
        && check.isBigInteger(this.blinding_factor)
        && check.isBigInteger(this.hashed_token);
  }

  /**
   * To encode RSA signature data the data is first hashed
   * and then encoded with the EMSA-PKCS1-v1_5 method.
   *
   * @param {Buffer} data
   *    a {Buffer} containing the prepared signature data
   * @param {hash.Hasher} hasher
   *    the algorithm used to hash the data
   * @returns {BigInteger}
   *    the encoded and padded rsa signature data
   */
  public encodeSignaturePayload(data: Buffer, hasher: hash.Hasher): BigInteger {
    assert(check.isBuffer(data));
    assert(check.isFunction(hasher));

    if (this.modulus == null) {
      throw new Error("Missing modulus.");
    }

    const hashed_data = hasher(data);
    const target_length = this.modulus.mpi_byte_length();

    return emsa_pkcs1_encode(hashed_data, target_length, { hasher });
  }
}

// ---------------------------------------------------------
// Following stuff is pure copy&paste from kbpgp source
// which is not exposed to their public interface.

const hash_headers: {[key: string]: number[]} = {
  MD5 : [
    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10,
  ],
  SHA1 : [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
  ],
  SHA224 : [
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C,
  ],
  SHA256 : [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ],
  SHA384 : [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
  ],
  SHA512 : [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
  ],
};

/** Create a EMSA-PKCS1-v1_5 padding (See RFC4880 13.1.3). */
function emsa_pkcs1_encode(hashed_data: Buffer, len: number,
                           opts = { hasher: hash.SHA256 }): BigInteger {

  const headers = hash_headers[opts.hasher.algname];
  const n = len - headers.length - 3 - opts.hasher.output_length;

  const padding: Buffer = new Buffer(n);
  padding.fill(0xff);

  const buf = Buffer.concat([
      new Buffer([ 0x00, 0x01 ]),
      padding,
      new Buffer([0x00]),
      new Buffer(headers),
    hashed_data ],
  );

  // We have to convert to a Uint8 array since the JSBN library internally
  // uses A[.] rather than A.readUint8(.)...
  return bn.nbs(String.fromCharCode.apply(null, util.buffer_to_ui8a(buf)), 256);
}
