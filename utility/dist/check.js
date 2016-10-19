"use strict";
var types_1 = require("./types");
function assert(condition, message) {
    if (!condition) {
        throw new Error(message || "Assertion failed");
    }
}
exports.assert = assert;
function isBigInteger(object) {
    return isObject(object) && (object instanceof types_1.BigInteger);
}
function isBuffer(object) {
    return isObject(object) && (object instanceof types_1.Buffer);
}
function isCurve(object) {
    return isObject(object) && (object instanceof types_1.Curve);
}
function isFunction(object) {
    return (typeof object === "function");
}
function isInteger(object) {
    return (typeof object === "number") && (object % 1 === 0);
}
function isObject(object) {
    return object === Object(object);
}
function isKeyManager(key_manager) {
    return (key_manager instanceof types_1.KeyManager)
        && (key_manager.get_primary_keypair() !== null);
}
function isKeyManagerForEcdsaSign(key_manager) {
    if (!isKeyManager(key_manager)) {
        return false;
    }
    var tmp = new types_1.KeyManager();
    var tags = types_1.Tags.public_key_algorithms;
    var key_algorithm = key_manager.get_primary_keypair().get_type();
    return (key_algorithm === tags.ECDSA);
}
function isKeyManagerForRsaSign(key_manager) {
    if (!isKeyManager(key_manager)) {
        return false;
    }
    var key_algorithm = key_manager.get_primary_keypair().get_type();
    var tags = types_1.Tags.public_key_algorithms;
    return (key_algorithm === tags.RSA) || (key_algorithm === tags.RSA_SIGN_ONLY);
}
function isPoint(object) {
    return isObject(object) && (object instanceof types_1.Point);
}
function isString(object) {
    return (typeof object === "string");
}
var check_api = {
    assert: assert,
    isBigInteger: isBigInteger,
    isBuffer: isBuffer,
    isCurve: isCurve,
    isFunction: isFunction,
    isInteger: isInteger,
    isKeyManager: isKeyManager,
    isKeyManagerForEcdsaSign: isKeyManagerForEcdsaSign,
    isKeyManagerForRsaSign: isKeyManagerForRsaSign,
    isObject: isObject,
    isPoint: isPoint,
    isString: isString
};
exports.__esModule = true;
exports["default"] = check_api;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2hlY2suanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvY2hlY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsWUFBWSxDQUFDO0FBRWIsaUNBQTZFO0FBVzdFLGdCQUFnQixTQUFrQixFQUFFLE9BQWlCO0lBRW5ELEVBQUUsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQztRQUNmLE1BQU0sSUFBSSxLQUFLLENBQUMsT0FBTyxJQUFJLGtCQUFrQixDQUFDLENBQUM7SUFDakQsQ0FBQztBQUNILENBQUM7QUEwTFEsaUJBL0xBLE1BQU0sQ0ErTEE7QUEvS2Ysc0JBQXNCLE1BQWU7SUFFbkMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sWUFBWSxrQkFBVSxDQUFDLENBQUM7QUFDNUQsQ0FBQztBQVdELGtCQUFrQixNQUFlO0lBRS9CLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLFlBQVksY0FBTSxDQUFDLENBQUM7QUFDeEQsQ0FBQztBQVdELGlCQUFpQixNQUFlO0lBRTlCLE1BQU0sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLFlBQVksYUFBSyxDQUFDLENBQUM7QUFDdkQsQ0FBQztBQVdELG9CQUFvQixNQUFlO0lBRWpDLE1BQU0sQ0FBQyxDQUFDLE9BQU8sTUFBTSxLQUFLLFVBQVUsQ0FBQyxDQUFDO0FBQ3hDLENBQUM7QUFXRCxtQkFBbUIsTUFBZTtJQUVoQyxNQUFNLENBQUMsQ0FBQyxPQUFPLE1BQU0sS0FBSyxRQUFRLENBQUMsSUFBSSxDQUFDLE1BQU0sR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7QUFDNUQsQ0FBQztBQVdELGtCQUFrQixNQUFlO0lBRS9CLE1BQU0sQ0FBQyxNQUFNLEtBQUssTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ25DLENBQUM7QUFXRCxzQkFBc0IsV0FBb0I7SUFFeEMsTUFBTSxDQUFDLENBQUMsV0FBVyxZQUFZLGtCQUFVLENBQUM7V0FDbkMsQ0FBQyxXQUFXLENBQUMsbUJBQW1CLEVBQUUsS0FBSyxJQUFJLENBQUMsQ0FBQztBQUN0RCxDQUFDO0FBWUQsa0NBQWtDLFdBQW9CO0lBRXBELEVBQUUsQ0FBQyxDQUFDLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUM7SUFBQyxDQUFDO0lBRWpELElBQU0sR0FBRyxHQUFnQixJQUFJLGtCQUFVLEVBQUUsQ0FBQztJQUMxQyxJQUFNLElBQUksR0FBRyxZQUFJLENBQUMscUJBQXFCLENBQUM7SUFDeEMsSUFBTSxhQUFhLEdBQWdCLFdBQVksQ0FBQyxtQkFBbUIsRUFBRSxDQUFDLFFBQVEsRUFBRSxDQUFDO0lBRWpGLE1BQU0sQ0FBQyxDQUFDLGFBQWEsS0FBSyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDeEMsQ0FBQztBQVlELGdDQUFnQyxXQUFvQjtJQUVsRCxFQUFFLENBQUMsQ0FBQyxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFBQyxNQUFNLENBQUMsS0FBSyxDQUFDO0lBQUMsQ0FBQztJQUVqRCxJQUFNLGFBQWEsR0FBZ0IsV0FBWSxDQUFDLG1CQUFtQixFQUFFLENBQUMsUUFBUSxFQUFFLENBQUM7SUFDakYsSUFBTSxJQUFJLEdBQUcsWUFBSSxDQUFDLHFCQUFxQixDQUFDO0lBRXhDLE1BQU0sQ0FBQyxDQUFDLGFBQWEsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxhQUFhLEtBQUssSUFBSSxDQUFDLGFBQWEsQ0FBQyxDQUFDO0FBQ2hGLENBQUM7QUFXRCxpQkFBaUIsTUFBZTtJQUU5QixNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxZQUFZLGFBQUssQ0FBQyxDQUFDO0FBQ3ZELENBQUM7QUFXRCxrQkFBa0IsTUFBZTtJQUUvQixNQUFNLENBQUMsQ0FBQyxPQUFPLE1BQU0sS0FBSyxRQUFRLENBQUMsQ0FBQztBQUN0QyxDQUFDO0FBRUQsSUFBTSxTQUFTLEdBQUc7SUFDaEIsTUFBTSxRQUFBO0lBQ04sWUFBWSxjQUFBO0lBQ1osUUFBUSxVQUFBO0lBQ1IsT0FBTyxTQUFBO0lBQ1AsVUFBVSxZQUFBO0lBQ1YsU0FBUyxXQUFBO0lBQ1QsWUFBWSxjQUFBO0lBQ1osd0JBQXdCLDBCQUFBO0lBQ3hCLHNCQUFzQix3QkFBQTtJQUN0QixRQUFRLFVBQUE7SUFDUixPQUFPLFNBQUE7SUFDUCxRQUFRLFVBQUE7Q0FDVCxDQUFDOztBQUVGLHFCQUFlLFNBQVMsQ0FBQyJ9