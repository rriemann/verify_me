declare module "kbpgp" {
    
    namespace asym  {

        namespace RSA {

            function generate(options: Object, fn:(error: string, key: Pair) => void): void;

            class Pair {

                pub: Pub
                priv: Priv

                get_type(): string;
            }

            class Priv {

                p: bn.BigInteger
                q: bn.BigInteger
            }

            class Pub {}
        }
    }

    namespace bn {

        class BigInteger {

            static ZERO: BigInteger
            static ONE: BigInteger
            static TWO: BigInteger

            static fromBuffer(buffer: Buffer): BigInteger;

            compareTo(other: BigInteger): number;
            multiply(other: BigInteger): BigInteger;
            toBuffer(): Buffer;
        }
    }

    namespace ecc.curves {
        
        class Curve {

            n: bn.BigInteger

            random_scalar(fn:(scalar: bn.BigInteger) => void): any;
        }
    }

    namespace hash {
        
        function SHA512(buffer: Buffer): Buffer
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
    
    class Buffer {}

    class KeyManager {
        
        get_primary_keypair(): asym.RSA.Pair
        import_from_armored_pgp(args: Object, fn:(error: string, keyManager: KeyManager) => void): KeyManager
    }
}