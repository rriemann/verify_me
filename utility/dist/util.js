"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments)).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t;
    return { next: verb(0), "throw": verb(1), "return": verb(2) };
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var kbpgp = require("kbpgp");
var check_1 = require("./check");
var types_1 = require("./types");
function generateKeyFromString(key_as_string) {
    return new Promise(function (resolve, reject) {
        check_1.assert(check_1["default"].isString(key_as_string), "Input parameter is not of type string.");
        types_1.KeyManager.prototype.import_from_armored_pgp({ armored: key_as_string }, function (err, key_manager) {
            if (err) {
                reject(err);
            }
            else {
                resolve(key_manager);
            }
        });
    });
}
function generateRandomScalar(curve) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            check_1.assert(check_1["default"].isCurve(curve));
            return [2 /*return*/, new Promise(function (resolve, reject) {
                    return curve.random_scalar(function (k) {
                        check_1.assert(k.compareTo(types_1.BigInteger.ZERO) >= 0);
                        check_1.assert(k.compareTo(curve.n) < 0);
                        resolve(k);
                    });
                })];
        });
    });
}
function generateRsaBlindingFactor(bitLength) {
    return __awaiter(this, void 0, void 0, function () {
        var sub_prime_length, primes;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    check_1.assert(check_1["default"].isInteger(bitLength), "The blinding factor bit length is no integer but a '" + bitLength + "'");
                    check_1.assert((bitLength % 8 === 0) && bitLength >= 256 && bitLength <= 16384, "The blinding factor bit length must be a multiple of 8 bits and >= 256 and <= 16384");
                    sub_prime_length = Math.floor(bitLength / 2);
                    return [4 /*yield*/, generateTwoPrimeNumbers(sub_prime_length)];
                case 1:
                    primes = _a.sent();
                    return [2 /*return*/, primes[0].multiply(primes[1])];
            }
        });
    });
}
function generateTwoPrimeNumbers(primeBitLength) {
    return new Promise(function (resolve, reject) {
        check_1.assert(check_1["default"].isInteger(primeBitLength), "The prime bit length is no integer but a '" + primeBitLength + "'");
        check_1.assert((primeBitLength % 8 === 0) && primeBitLength >= 128 && primeBitLength <= 8192, "The prime bit length must be a multiple of 8 bits and >= 128 and <= 8192");
        var key_arguments = {
            e: 65537,
            nbits: primeBitLength * 2
        };
        kbpgp.asym.RSA.generate(key_arguments, function (err, key) {
            if (err) {
                reject(err);
            }
            resolve([key.priv.p, key.priv.q]);
        });
    });
}
function calculateSha512(message) {
    check_1.assert(check_1["default"].isBigInteger(message));
    var hash_buffer = kbpgp.hash.SHA512(message.toBuffer());
    return types_1.BigInteger.fromBuffer(hash_buffer);
}
var util_api = {
    generateKeyFromString: generateKeyFromString,
    generateRandomScalar: generateRandomScalar,
    generateRsaBlindingFactor: generateRsaBlindingFactor,
    generateTwoPrimeNumbers: generateTwoPrimeNumbers,
    calculateSha512: calculateSha512
};
exports.__esModule = true;
exports["default"] = util_api;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3NyYy91dGlsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQVksQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBRWIsNkJBQThCO0FBRTlCLGlDQUF3QztBQUN4QyxpQ0FBdUQ7QUFVdkQsK0JBQStCLGFBQXNCO0lBRW5ELE1BQU0sQ0FBQyxJQUFJLE9BQU8sQ0FBQyxVQUFDLE9BQU8sRUFBRSxNQUFNO1FBRWpDLGNBQU0sQ0FBQyxrQkFBSyxDQUFDLFFBQVEsQ0FBQyxhQUFhLENBQUMsRUFBRSx3Q0FBd0MsQ0FBQyxDQUFDO1FBRWhGLGtCQUFVLENBQUMsU0FBUyxDQUFDLHVCQUF1QixDQUFDLEVBQUUsT0FBTyxFQUFFLGFBQWEsRUFBRSxFQUNyRSxVQUFDLEdBQVksRUFBRSxXQUF3QjtZQUNyQyxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUFDLENBQUM7WUFDekIsSUFBSSxDQUFDLENBQUM7Z0JBQ0osT0FBTyxDQUFhLFdBQVcsQ0FBQyxDQUFDO1lBQ25DLENBQUM7UUFDSCxDQUFDLENBQUMsQ0FBQztJQUNQLENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQWFELDhCQUFvQyxLQUFhOzs7WUFFL0MsY0FBTSxDQUFDLGtCQUFLLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7WUFFN0IsTUFBTSxnQkFBQyxJQUFJLE9BQU8sQ0FBQyxVQUFDLE9BQU8sRUFBRSxNQUFNO29CQUNqQyxPQUFBLEtBQUssQ0FBQyxhQUFhLENBQ2pCLFVBQUEsQ0FBQzt3QkFHQyxjQUFNLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxrQkFBVSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO3dCQUMxQyxjQUFNLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxLQUFL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