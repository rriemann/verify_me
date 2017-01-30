// Type definitions for keybase-ecurve 1.0.0
// Project: https://github.com/keybase/keybase-ecurve
// Definitions by: Bruno Kirschner <https://gitlab.com/0ndo>
// Definitions: https://gitlab.com/0ndo/verify_me.git

/// <reference types="bn" />
import { BigInteger } from "bn"

declare module "keybase-ecurve" {
    
    class Point {
        
        affineX: BigInteger;
        affineY: BigInteger;
        
        add(other: Point): Point;
        multiply(other: BigInteger): Point;
    }
}
