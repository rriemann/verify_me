// Type definitions for kbpgp 2.0.58
// Project: https://github.com/keybase/kbpgp
// Definitions by: Bruno Kirschner <https://gitlab.com/0ndo>
// Definitions: https://gitlab.com/0ndo/verify_me.git

/// <refeence types="keybase-ecurve" />
import ecurve = require("keybase-ecurve");

declare namespace kbpgp {
    namespace asym  {

        namespace RSA {

            function generate(options: Object, fn:(error: string, key: Pair) => void): void;

            class Pair {

                pub: Pub;
                priv: Priv;

                get_type(): string;
            }

            class Priv {

                p: bn.BigInteger;
                q: bn.BigInteger;
            }

            class Pub {}
        }
    }

    namespace bn {

        class BigInteger {

            static ZERO: BigInteger;
            static ONE: BigInteger;
            static TWO: BigInteger;

            static fromBuffer(buffer: Buffer): BigInteger;

            bitLength(): number;
            compareTo(other: BigInteger): number;
            isProbablePrime(): boolean;
            multiply(other: BigInteger): BigInteger;
            toBuffer(): Buffer;
            toString(base: number): string;
        }
    }
    
    namespace ecc.curves {

        function brainpool_p512(): Curve;
        
        class Curve {

            n: bn.BigInteger;
            G: ecurve.Point;

            random_scalar(fn:(scalar: bn.BigInteger) => void): any;
        }
    }

    namespace hash {
        
        function SHA512(buffer: Buffer): Buffer;
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
    
    class Buffer {

        constructor(content: string);
        constructor(content: number);
    }

    class KeyManager {

        constructor(_args:Object);
        
        get_primary_keypair(): asym.RSA.Pair;
        static import_from_armored_pgp(args: any, fn:(error: string, keyManager: KeyManager) => void): KeyManager;
    }
}

export = kbpgp;