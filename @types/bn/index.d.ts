// Type definitions for INSERT PROJECT NAME HERE
// Project: http://example.com/THE_PROJECT_WEBSITE
// Definitions by: Your Name <YOUR_GITHUB_PROFILE_OR_EMAIL>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

// Definition file started by dts-gen

export namespace BigInteger {
    
    const ZERO: BigInteger;
    const ONE: BigInteger;
    const TWO: BigInteger;
}

export class BigInteger {

    constructor(value: string, radix: number);
    constructor(a: any, b: any, c: any);

    abs(): any;
    add(a: any): any;
    addTo(a: any, r: any): void;
    am(i: any, x: any, w: any, j: any, c: any, n: any): any;
    and(a: any): any;
    andNot(a: any): any;
    bitCount(): any;
    bitLength(): any;
    bitwiseTo(a: any, op: any, r: any): void;
    byteLength(): any;
    byteValue(): any;
    changeBit(n: any, op: any): any;
    chunkSize(r: any): any;
    clamp(): void;
    clearBit(n: any): any;
    clone(): any;
    compareTo(a: any): any;
    copyTo(r: any): void;
    dAddOffset(n: any, w: any): void;
    dMultiply(n: any): void;
    divRemTo(m: any, q: any, r: any): void;
    divide(a: any): any;
    divideAndRemainder(a: any): any;
    dlShiftTo(n: any, r: any): void;
    drShiftTo(n: any, r: any): void;
    equals(a: any): any;
    exp(e: any, z: any): any;
    flipBit(n: any): any;
    fromBuffer(buf: any): any;
    fromInt(x: any): void;
    fromNumber(a: any, b: any, c: any): void;
    fromRadix(s: any, b: any): void;
    fromString(s: any, b: any, unsigned: any): any;
    gcd(a: any): any;
    getLowestSetBit(): any;
    inspect(): any;
    intValue(): any;
    invDigit(): any;
    isEven(): any;

    isProbablePrime(certainty_factor: number): boolean;
    isProbablePrime(): boolean;    

    lShiftTo(n: any, r: any): void;
    max(a: any): any;
    millerRabin(t: any): any;
    min(a: any): any;
    mod(a: any): any;
    modInt(n: any): any;
    modInverse(m: any): any;
    modPow(e: any, m: any): any;
    modPowInt(e: any, m: any): any;
    multiply(a: any): any;
    multiplyLowerTo(a: any, n: any, r: any): void;
    multiplyTo(a: any, r: any): void;
    multiplyUpperTo(a: any, n: any, r: any): void;
    negate(): any;
    not(): any;
    or(a: any): any;
    pow(e: any): any;
    rShiftTo(n: any, r: any): void;
    remainder(a: any): any;
    setBit(n: any): any;
    shiftLeft(n: any): any;
    shiftRight(n: any): any;
    shortValue(): any;
    signum(): any;
    square(): any;
    squareTo(r: any): void;
    subTo(a: any, r: any): void;
    subtract(a: any): any;
    testBit(n: any): any;
    toBuffer(): any;
    toBuffer(size: any): any;
    toByteArray(encode_sign_bit: any): any;
    toByteArrayUnsigned(): any;
    toDERInteger(): any;
    toHex(size: any): any;
    toMPI(): any;
    toRadix(base: number): string;
    toString(b: any): any;
    xor(a: any): any;
    static fromBuffer(buf: any): any;
    static fromByteArrayUnsigned(b: any): any;
    static fromDERInteger(buf: any): any;
    static fromHex(s: any): any;
    static random_nbit(nbits: any, rf: any): any;
    static valueOf(x: any): any;
}
export class Classic {
    constructor(m: any);
    convert(x: any): any;
    mulTo(x: any, y: any, r: any): void;
    reduce(x: any): void;
    revert(x: any): any;
    sqrTo(x: any, r: any): void;
}
export class Montgomery {
    constructor(m: any);
    convert(x: any): any;
    mulTo(x: any, y: any, r: any): void;
    reduce(x: any): void;
    revert(x: any): any;
    sqrTo(x: any, r: any): void;
}
export function nbi(): any;
export function nbits(x: any): any;
export function nbv(i: any): any;
