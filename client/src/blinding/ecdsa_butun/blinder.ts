"use strict";

import {
  assert, BigInteger, Buffer, check, Curve, KeyManager, Point, util,
} from "verifyme_utility";

import BlindSignaturePacket from "../../pgp/blind_signature_packet";
import Blinder from "../blinder";
import ButunEcdsaBlindingContext from "./blinding_context";

import server from "../../server_requests";

/**
 * Representation of the ECDSA blinding algorithm presented by Ismail Butun and Mehmet Demirer
 * in "A blind digital signature scheme using elliptic curve digital signature algorithm"
 *
 * http://journals.tubitak.gov.tr/elektrik/issues/elk-13-21-4/elk-21-4-4-1102-1051.pdf
 *
 * The variable naming follows the algorithms notation.
 */
export default class ButunEcdsaBlinder extends Blinder<ButunEcdsaBlindingContext> {

  public hashed_token: BigInteger;
  public signer: Point;
  public requester: Point;

  constructor() {
    super();
  };

  /**
   * Initializes the internal {ButunEcdsaBlindingContext}.
   *
   * @param {KeyManager} key_manager
   *    A {KeyManager} containing the signers public key which is necessary
   *    to extract the elliptic curve public .
   * @param {BigInteger} token
   *    This is used to validate the blinded request.
   */
  public async initContext(key_manager: KeyManager, token: BigInteger): Promise<void> {
    assert(check.isKeyManagerForEcdsaSign(key_manager));
    assert(check.isBigInteger(token));

    const context = ButunEcdsaBlindingContext.fromKey(key_manager);
    if (context.curve === null) {
      throw new Error("context.curve must not be null");
    }

    const curve: Curve = context.curve;
    context.blinding_factor = {
      a: await util.generateRandomScalar(curve),
      b: await util.generateRandomScalar(curve),
    };

    context.hashed_token = util.calculateSha512(token);

    this.context = context;
    this.key_manager = key_manager;
    this.token = token;

    const {signer, requester} =  await this.requestPublicPoints();
    this.signer = signer;
    this.requester = requester;
  }

  /**
   * Blinds the given message.
   *
   *    blinding_factor_a * message * signers_public_point * inverse_requester_public_point (mod N)
   *
   * @param {BigInteger} message
   *    The original message.
   * @param {{signer: Point, requester: Point}} public_points
   *    An {object} containing the requesters and
   *    signers public blinding points.
   *
   * @returns {BigInteger}
   *    The blinded message.
   */
  public blind(message: BigInteger): BigInteger {
    assert(check.isBigInteger(message));
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const context: ButunEcdsaBlindingContext = this.context as ButunEcdsaBlindingContext;
    if (context.curve === null) {
      throw new Error("Context must not be null.");
    }

    const n = context.curve.n;
    const a = context.blinding_factor.a;
    if (a === null) {
      throw new Error("Blinding factor a must not be null.");
    }

    const R = this.requester;
    const r = R.affineX.mod(n);
    const r_inv = r.modInverse(n);

    const Ŕ = this.signer;
    const ŕ = Ŕ.affineX.mod(n);

    return a.multiply(message).multiply(ŕ).multiply(r_inv).mod(n);
  }

  /**
   * Unblinds the given signed blinded message.
   *
   *    (signed_blinded_message * requester_public_point * inverse_signers_public_point)
   *    + (blinding_factor_b * original_message) (mod N)
   *
   * @param {BigInteger} message
   *    The signed blinded message.
   * @param {BigInteger} original_message
   *    The message to be signed.
   *
   * @returns {BigInteger}
   *    The unblinded signed message.
   */
  public unblind(signed_blinded_message: BigInteger, original_message: BigInteger): BigInteger {
    assert(check.isBigInteger(signed_blinded_message));
    assert(check.isBigInteger(original_message));
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const context = this.context as ButunEcdsaBlindingContext;
    if (context.curve === null) {
      throw new Error("Context curve must not be null.");
    }

    const n = context.curve.n;
    assert(signed_blinded_message.compareTo(BigInteger.ZERO) > 0);
    assert(signed_blinded_message.compareTo(n) < 0);

    const R = this.requester;
    const r = R.affineX.mod(n);

    const Ŕ = this.signer;
    const ŕ = Ŕ.affineX.mod(n);
    const ŕ_inv = ŕ.modInverse(n);

    const b = context.blinding_factor.b;
    if (b === null) {
      throw new Error("Blinding factor b must not be null.");
    }

    const bm = b.multiply(original_message);
    return signed_blinded_message.multiply(r).multiply(ŕ_inv).add(bm).mod(n);
  }

  /**
   * Forges a Butun ecdsa based blind signature.
   *
   * To achieve this the prepared raw signature is blinded and send to the server.
   * The server signs the blinded message and the result is send back.
   * Afterwards the result is unblinded and inject into the given signature packet.
   *
   * Based on: http://journals.tubitak.gov.tr/elektrik/issues/elk-13-21-4/elk-21-4-4-1102-1051.pdf
   *
   * @param {BlindSignaturePacket} packet
   *    The prepared {BlindSignaturePacket} including the raw signature.
   */
  public async forgeSignature(packet: BlindSignaturePacket): Promise<void> {
    assert(packet instanceof BlindSignaturePacket);
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const context = this.context as ButunEcdsaBlindingContext;
    if (context.curve === null) {
      throw new Error("Curve must not be null.");
    }

    const hash = util.calculateSha512(packet.raw_signature);
    const message = packet.key.pub.trunc_hash(hash.toBuffer());

    const blinded_message = this.blind(message);

    const signed_blinded_message = await server.requestButunEcdsaBlinding(blinded_message, context);
    if (signed_blinded_message instanceof Error) {
      throw signed_blinded_message;
    }

    const signed_message = this.unblind(signed_blinded_message, message);

    const signature = Buffer.concat([
      signed_message.to_mpi_buffer(),
      context.curve.point_to_mpi_buffer(this.requester),
    ]);

    packet.sig = signature;
    packet.raw = packet.write_unframed();
  }

  /**
   * Calculates the public blinding information which are
   * Necessary to blind and unblind the message.
   *
   * @returns {{signer: Point, requester: Point}}
   *    Signers and requester public curve point.
   */
  private async requestPublicPoints(): Promise<{signer: Point, requester: Point}> {
    assert(ButunEcdsaBlindingContext.isValidBlindingContext(this.context));

    const context = this.context as ButunEcdsaBlindingContext;
    if (context.curve === null) {
      throw new Error("Context curve must not be null.");
    }

    const curve = context.curve;
    const n = curve.n;
    const G = curve.G;
    const a = context.blinding_factor.a;
    const b = context.blinding_factor.b;
    if (a === null || b === null) {
      throw new Error("Blinding factor a and b must not be null.");
    }

    const Ŕ = await server.requestButunEcdsaInitialization(context);
    if (Ŕ instanceof Error) {
      throw Ŕ;
    }

    assert(curve.isOnCurve(Ŕ));

    const ŕ = Ŕ.affineX.mod(n);
    assert(ŕ.compareTo(BigInteger.ZERO) > 0);
    assert(ŕ.compareTo(n) < 0);

    const aŔ = Ŕ.multiply(a);
    const bG = G.multiply(b);
    const R = aŔ.add(bG);
    assert(curve.isOnCurve(R));

    return { signer: Ŕ, requester: R };
  }
}
