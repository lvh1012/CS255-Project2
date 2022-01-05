/* This file contains utility functions for lib.js
YOU SHOULD NOT NEED TO USE ANYTHING IN THIS FILE */

"use strict";
import sjcl from "./sjcl";
export function setupCipher(key) {
    if (bitarrayLen(key) != 128) {
        throw "setupCipher: only accepts keys for AES-128"
    }
    return new sjcl.cipher.aes(key)
};
export function bitarraySlice(bitarray, a, b) {
    return sjcl.bitArray.bitSlice(bitarray, a, b)
};
export function bitarrayToString(bitarray) {
    return sjcl.codec.utf8String.fromBits(bitarray)
};
export function stringToBitarray(str) {
    return sjcl.codec.utf8String.toBits(str)
};
export function bitarrayToHex(bitarray) {
    return sjcl.codec.hex.fromBits(bitarray)
};
export function hexToBitarray(hexStr) {
    return sjcl.codec.hex.toBits(hexStr)
};
export function bitarrayToBase64(bitarray) {
    return sjcl.codec.base64.fromBits(bitarray)
};
export function base64ToBitarray(base64Str) {
    return sjcl.codec.base64.toBits(base64Str)
};
export function byteArrayToHex(a) {
    let s = "";
    for (let i = 0; i < a.length; i++) {
        if (a[i] < 0 || a[i] >= 256) {
            throw "byteArrayToHex: value outside byte range"
        }
        s += ((a[i] | 0) + 256).toString(16).substr(1)
    }
    return s
};
export function hexToByteArray(s) {
    let a = [];
    if (s.length % 2 != 0) {
        throw "hexToByteArray: odd length"
    }
    for (let i = 0; i < s.length; i += 2) {
        a.push(parseInt(s.substr(i, 2), 16) | 0)
    }
    return a
};
export function wordToBytesAcc(word, bytes) {
    if (word < 0) {
        throw "wordToBytesAcc: can't convert negative integer"
    }
    for (let i = 0; i < 4; i++) {
        bytes.push(word & 0xff);
        word = word >>> 8
    }
};
export function wordFromBytesSub(bytes, i_start) {
    if (!Array.isArray(bytes)) {
        console.log(bytes);
        console.trace();
        throw "wordFromBytesSub: received non-array"
    }
    if (bytes.length < 4) {
        throw "wordFromBytesSub: array too short"
    }
    let word = 0;
    for (let i = i_start + 3; i >= i_start; i--) {
        word <<= 8;
        word |= bytes[i]
    }
    return word
};
export function randomBitarray(len) {
    if (len % 32 != 0) {
        throw "random_bit_array: len not divisible by 32"
    }
    return sjcl.random.randomWords(len / 32, 0)
};
export function bitarrayEqual(a1, a2) {
    return sjcl.bitArray.equal(a1, a2)
};
export function bitarrayLen(a) {
    return sjcl.bitArray.bitLength(a)
};
export function bitarrayConcat(a1, a2) {
    return sjcl.bitArray.concat(a1, a2)
};
export function objectHasKey(obj, key) {
    return obj.hasOwnProperty(key)
}
