// Type definitions for kbpgp 2.0.58
// Project: https://github.com/keybase/kbpgp
// Definitions by: Bruno Kirschner <https://gitlab.com/0ndo>
// Definitions: https://gitlab.com/0ndo/verify_me.git

/// <reference types="node" />
/// <reference types="bn" />
/// <reference types="keybase-ecurve" />

import * as bigint from "bn";
import { Point } from "keybase-ecurve";

export { Buffer } from "buffer"
export import bn = bigint;

declare module "bn" {

    function nbi(): BigInteger;
    function nbits(x: BigInteger): number;
    function nbs(number: string, base: number): BigInteger;
    function nbv(value: number): BigInteger;

    interface BigInteger {

    	mpi_byte_length(): number;
        to_mpi_buffer(): Buffer;
    }
}

export namespace armor {

    function encode(type: number, data: number[]): string; 
}

export namespace asym {

    namespace RSA {

        function generate(options: Object, fn:(error: string, key: Pair) => void): void;

        class Pair implements BaseKeyPair {

            pub: Pub;
            priv: Priv;
            type: number;

            get_type(): number;
        }

        class Priv implements PrivateKey {

            d: bn.BigInteger;
            p: bn.BigInteger;
            q: bn.BigInteger;
        }

        class Pub implements PublicKey {
            
            e: bn.BigInteger;
            n: bn.BigInteger;

            trunc_hash(hash: Buffer): bn.BigInteger;
        }
    }
}

export namespace hash {

    type Hasher = {
        (data: Buffer): Buffer;

        algname: string;
        output_length: number;
        type: number;
    }

    const MD5: Hasher;
    const SHA256: Hasher;
    const SHA512: Hasher;
}

export namespace util {

    function assert_no_nulls(value: Object[]): void;
    function buffer_to_ui8a(value: Buffer): Uint8Array;
    function uint_to_buffer(value: number, buffer_length: number): Buffer;
}

// As it seems it is not possible to define a namespace/variable named "const".
// If we want to access it we have to cast the kbpgp import to <any>.
// i.e:
//
//   impor * as kbpgp from "kbpgp"
//   var kbpgp_consts = (<any>kbpgp).const
//
//
// const "const": Map<String, String>

export interface BaseKeyPair {

    pub: PublicKey;
    priv: PrivateKey;
    type: number;

    get_type(): number;
}

export interface BaseKey {

    serialize(): Buffer;
    validity_check(cb: Function): void;
}

export namespace ecc {

    abstract class BaseEccKey implements BaseKey {

        curve: curves.Curve;
        R: Point;

        serialize(): Buffer;
        validity_check(cb: Function): void;
    }

    namespace curves {

        function brainpool_p512(): Curve;
    
        class Curve {

            n: bn.BigInteger;
            G: Point;

            isOnCurve(point: Point): boolean;
            mkpoint(coordinates: {x: bn.BigInteger, y: bn.BigInteger}): Point;
            point_to_mpi_buffer(point: Point): Buffer;
            random_scalar(fn:(scalar: bn.BigInteger) => void): any;
        }
    }

    namespace ECDSA {

        class Pub extends BaseEccKey {

            type: number;

            nbits(): number;
            trunc_hash(hash: Buffer): bn.BigInteger;
        }

        class Priv extends BaseEccKey {

            pub: Pub;
            x: bigint.BigInteger;

            sign(hash: Buffer, cb: (r: bigint.BigInteger, s: bigint.BigInteger) => void): void;
        }

        class Pair implements BaseKeyPair {

            klass_name: string;
            priv: Priv;
            pub: Pub;

            type: number;

            get_type(): number;
        }
    }

    namespace ECDH {
        
        class Pub extends BaseEccKey {

            trunc_hash(hash: Buffer): bn.BigInteger;
        }

        class Priv extends BaseEccKey {

            pub: Pub;
            x: bigint.BigInteger;

            decrypt(hash: Buffer, cb: (r: bigint.BigInteger, s: bigint.BigInteger) => void): void;
        }

        class Pair implements BaseKeyPair {

            klass_name: string;
            priv: Priv;
            pub: Pub;

            type: number;

            get_type(): number;
        }
    }

    namespace EDDSA {

        class Pub extends BaseEccKey {

            trunc_hash(hash: Buffer): bn.BigInteger;
        }
    }
}

export interface PublicKey {
    trunc_hash(hash: Buffer): bn.BigInteger;
}

export interface PrivateKey {}

export class LifeSpan {

    generated: number;
    expire_in: number;
}

export class Engine {

    primary: KeyWrapper;
    subkeys: KeyWrapper[];
}

export class PgpEngine extends Engine {

    userids: opkts.UserID[];

    key(wrapper: KeyWrapper): opkts.KeyMaterial;
}

export class KeyWrapper {

    key: asym.RSA.Pair;
    lifespan: LifeSpan;
    _pgp: opkts.KeyMaterial;
}

export class Subkey extends KeyWrapper {

}

export class Primary extends KeyWrapper {
    
    primary: boolean;
}

export class KeyManager {

    armored_pgp_public: string;
    pgp: PgpEngine;
    primary: KeyWrapper;

    constructor(_args:Object);
    
    get_pgp_key_id(): Buffer;
    get_primary_keypair(): BaseKeyPair;
    get_userids(): opkts.UserID[];
    get_userids_mark_primary(): opkts.UserID[];

    merge_pgp_private(args: any, cb: (error: Error) => void): void;
    unlock_pgp(args: {passphrase: string} ,cb: (error: Error) => void): void;

    static import_from_armored_pgp(args: any, fn:(error: string, keyManager: KeyManager) => void): KeyManager;
}

export namespace opkts {

    namespace packetSignatures {
        
        abstract class Base {
            sig: Signature;
            key_expiration: KeyExpirationTime;
        }

        class Collection {
            all: Base[];
        }
    }

    class Packet {

        frame_packet(tag: number, body: Buffer): Buffer;
        get_psc(): packetSignatures.Collection;
        
        is_signature(): boolean;
        is_key_material(): boolean;
        is_duplicated_primary(): boolean;
        
        replay(): Buffer;
    }

    class SubPacket {

        critical: boolean;
        five_byte_len: boolean;

        constructor(type: number);

        to_buffer(): Buffer;
    }

    class Signature extends Packet {

        key: BaseKeyPair;
        key_id: Buffer;
        hashed_subpackets: SubPacket[];
        
        hasher: {
            (target: Buffer): Buffer;

            algname: string;
            output_length: number;
            type: number;
        }

        primary: KeyMaterial;
        public_key_class: number;
        sig: Buffer;
        sig_data: Buffer;
        signed_hash_value_hash: Buffer;
        time: number;
        type: number;
        unhashed_subpackets: SubPacket[];
        version: number;

        constructor(ctor_args: {
             key: BaseKeyPair,
             key_id: Buffer,
             type: number,
             version: number,
             hasher?: (target: Buffer) => Buffer,
             hashed_subpackets?: SubPacket[],
             public_key_class?: number,
             sig?: Buffer,
             sig_data?: Buffer,
             signed_hash_value_hash?: Buffer,
             time?: number,
             unhashed_subpackets?: SubPacket[]
        });

        extract_key(data_packets: any): void;
        get_key_expires(): Date;
        get_key_id(): Buffer;
        get_sig_expires(): Date;
        prepare_payload(data:any): any;
        verify(data_packets: Packet[], cb: (err: Error) => void):any;
        when_generated(): Date; 
        write_unframed(data:any, cb: any): void;
        write(data: any, cb: any): void;
    }

    class KeyMaterial extends Packet {

        constructor();

        export_framed(opts: Object): Buffer;
        get_subkey_binding_signature_output(): Buffer; 
        to_signature_payload(): Buffer;
    }

    class UserID extends Packet {

        get_framed_signature_output(): Buffer;
        to_signature_payload(): Buffer;
        write(): Buffer;
    }

    class Experimental extends SubPacket {}

    class Time extends SubPacket {

        time: number;    

        constructor(type: number, time: number);
    }

    class Preference extends SubPacket {}

    class CreationTime extends Time {

        constructor(time: number);
    }

    class ExpirationTime extends Time {}

    class Exportable extends SubPacket {}

    class Trust extends SubPacket {}

    class RegularExpression extends SubPacket {}

    class Revocable extends SubPacket {}

    class KeyExpirationTime extends Time {}

    class PreferredSymmetricAlgorithms extends Preference {}

    class RevicationKey extends SubPacket {}

    class Issuer extends SubPacket {

        id: Buffer;

        constructor(id: Buffer);
    }

    class NotationData extends SubPacket {}

    class PreferredHashAlgorithms extends Preference {}

    class PreferredCompressionAlgorithms extends Preference {}

    class KeyServerPreferences extends Preference {}

    class Features extends Preference {}

    class PreferredKeyServer extends SubPacket {}

    class PrimaryUserId extends SubPacket {}

    class PolicyURI extends SubPacket {}

    class KeyFlags extends Preference {}

    class EmbeddedSignature extends SubPacket {}

    class VerificationAlgorithm extends SubPacket {

        algorithm: number;

        constructor(algorithm: number);
    }
}
