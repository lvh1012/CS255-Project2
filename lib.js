"use strict";

import sjcl from "./sjcl";
import * as utils from "./lib-utils";

////////////////////////////////////////////////////////////////////////////////
//  Cryptographic Primitives
//
// All of the cryptographic functions you need for this assignment
// are contained within this library.
//
// For your convinience, we have abstracted away all of the pesky
// underlying data types (bitarrays, etc) so that you can focus
// on building messenger.js without getting caught up with conversions.
// Keys, hash outputs, ciphertexts, and signatures are always hex-encoded
// strings (except for ElGamal and DSA key pairs, which are objects),
// and input plaintexts are also strings (hex-encoded or not, either is fine).
////////////////////////////////////////////////////////////////////////////////

export function generateEG() {
  // returns a pair of ElGamal keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const pair = sjcl.ecc.elGamal.generateKeys(sjcl.ecc.curves.k256);
  let publicKey = pair.pub.get();
  publicKey = sjcl.codec.base64.fromBits(publicKey.x.concat(publicKey.y))
  let secretKey = pair.sec.get();
  secretKey = sjcl.codec.base64.fromBits(secretKey);
  const keypairObject = {
    pub: publicKey,
    sec : secretKey,
  }
  return keypairObject; // keypairObject.sec and keypairObject.pub are keys
};

export function computeDH(myPrivateKey, theirPublicKey) {
  // computes Diffie-Hellman key exchange for an EG private key and EG public key
  // myPrivateKey should be pair.sec from generateEG output
  // theirPublicKey should be pair.pub from generateEG output
  // myPrivateKey and theirPublicKey should be from different calls to generateEG
  // outputs shared secret result of DH exchange
  // result of DH exchange is hashed with SHA256
  // return value a hex-encoded string, 64 characters (256 encoded bits) hash output
  const rawSecKey = new sjcl.ecc.elGamal.secretKey(sjcl.ecc.curves.k256, sjcl.ecc.curves.k256.field.fromBits(sjcl.codec.base64.toBits(myPrivateKey)));
  const rawPubKey = new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.k256, sjcl.codec.base64.toBits(theirPublicKey));
  const bitarrayOutput = rawSecKey.dh(rawPubKey);
  return utils.bitarrayToHex(bitarrayOutput);
};

export function verifyWithECDSA(publicKey, message, signature) {
  // returns true if signature is correct for message and publicKey
  // publicKey should be pair.pub from generateECDSA
  // message must be a string
  // signature must be exact output of signWithECDSA
  // returns true if verification is successful, throws exception if fails
  const rawPubKey = new sjcl.ecc.ecdsa.publicKey(sjcl.ecc.curves.k256, sjcl.codec.base64.toBits(publicKey));
  const bitarraySignature = utils.hexToBitarray(signature);
  return rawPubKey.verify(sjcl.hash.sha256.hash(message), bitarraySignature);
};

export function HMACWithSHA256(key, data) {
  // Returns the HMAC on the data.
  // key is a hex-encoded string
  // data is a string (any encoding is fine)
  let hmacObject = new sjcl.misc.hmac(utils.hexToBitarray(key), sjcl.hash.sha256);
  const bitarrayOutput = hmacObject.encrypt(data);
  return utils.bitarrayToHex(bitarrayOutput);
};

export function HMACWithSHA512(key, data) {
  // Returns the HMAC on the data.
  // key is a hex-encoded string
  // data is a string (any encoding is fine)
  let hmacObject = new sjcl.misc.hmac(utils.hexToBitarray(key), sjcl.hash.sha512);
  const bitarrayOutput = hmacObject.encrypt(data);
  return utils.bitarrayToHex(bitarrayOutput);
};

export function SHA256(string) {
  // takes a string as input
  // outputs a hex-encoded string
  const bitarrayOutput = sjcl.hash.sha256.hash(string);
  return utils.bitarrayToHex(bitarrayOutput);
};

export function SHA512(string) {
  // takes a string as input
  // outputs a hex-encoded string
  const bitarrayOutput = sjcl.hash.sha512.hash(string);
  return utils.bitarrayToHex(bitarrayOutput);
};

export function HKDF(inputKey, outputKeyLenInBits, salt, infoStr) {

  //@inputKey: String of length 256
  //@outputKeyLenInBits: Desired key length in bits
  //               Note: HKDF throws if outputKeyLenInBits/256 > 255
  //@salt: String or Bitarray of length 256
  //@infoStr: String or Bitarray of arbitrary length. Entropy should be
  //          in the salt and inputkey. infoStr is intended to be a
  //          fixed string dependent on context (i.e. "ratchet-str").

  //@Return
  //Quick summary:
  //Function updates an HMAC in a loop (adds to the string that is being mac'd)
  //This hmac is keyed at the output of HMAC(key=salt, msg=inputKey), msg="")
  //The output is initialized to "".
  //Loops for outputKeyLenInBits/256 rounds:
  //    Each round updates the HMAC with <prevRoundOutput||infoStr||roundNumber>
  //    The digest after each round is appended to output.
  //Each digest is 256 bits, so return val has length outputKeyLenInBits after
  //outputKeyLenInBits/256 rounds. Note because roundNumber needs to be 1 byte,
  //outputKeyLenInBits/256 can't be greater than 255.

  const bitarrayOutput = sjcl.misc.hkdf(
                              utils.hexToBitarray(inputKey),
                              outputKeyLenInBits,
                              salt,
                              infoStr,
                              sjcl.hash.sha256);
  return utils.bitarrayToHex(bitarrayOutput);
};


export function encryptWithGCM(key, plaintext, authenticatedData) {
  // Encrypts using the GCM mode.
  // key is a hex-encoded string of length 32 (equivalent to 128 hex-encoded bits)
  // plaintext is a string of the message you want to encrypt.
  // authenticatedData is an optional argument string
  // returns hex-encoded ciphertext string
  // The authenticatedData is not encrypted into the ciphertext, but it will
  // not be possible to decrypt the ciphertext unless it is passed.
  // (If there is no authenticatedData passed when encrypting, then it is not
  // necessary while decrypting.)
  const bitarrayKey = utils.hexToBitarray(key);
  const cipher =utils.setupCipher(bitarrayKey);
  const iv = utils.randomBitarray(128);
  const bitarrayPT = utils.stringToBitarray(plaintext);
  const v = sjcl.mode.gcm.encrypt(cipher, bitarrayPT, iv, authenticatedData);
  const ciphertextBitarray = sjcl.bitArray.concat(iv, v);
  return utils.bitarrayToHex(ciphertextBitarray);
};

export function decryptWithGCM(key, ciphertext, authenticatedData) {
  // Decrypts using the GCM mode.
  // key is a hex-encoded string of length 32 (equivalent to 128 hex-encoded bits)
  // ciphertext has to be the output of a call to encryptWithGCM
  // authenticatedData is optional, but if it was passed when
  // encrypting, it has to be passed now, otherwise the decrypt will fail.
  // returns plaintext string if successful
  // throws exception if decryption fails (key incorrect, tampering detected, etc)
  const bitarrayKey = utils.hexToBitarray(key);
  const cipher =utils.setupCipher(bitarrayKey);
  const ciphertextBitarray = utils.hexToBitarray(ciphertext);
  let iv = sjcl.bitArray.bitSlice(ciphertextBitarray, 0, 128);
  let c = sjcl.bitArray.bitSlice(ciphertextBitarray, 128);
  const bitarrayPT = sjcl.mode.gcm.decrypt(cipher, c, iv, authenticatedData);
  return utils.bitarrayToString(bitarrayPT);
};

export function randomHexString(len) {
  if (len % 32 != 0) {
      throw "random_bit_array: len not divisible by 32";
  }
  const rawOutput = sjcl.random.randomWords(len / 32, 0);
  return utils.bitarrayToHex(rawOutput);
};

export function hexStringSlice(string, a, b) {
  const bitarray = utils.hexToBitarray(string);
  return utils.bitarrayToHex(sjcl.bitArray.bitSlice(bitarray, a, b));
};


////////////////////////////////////////////////////////////////////////////////
// Addtional ECDSA functions for test-messenger.js
//
// YOU DO NOT NEED THESE FUNCTIONS FOR MESSENGER.JS,
// but they may be helpful if you want to write additional
// tests for certificate signatures in test-messenger.js.
////////////////////////////////////////////////////////////////////////////////

export function generateECDSA() {
  // returns a pair of Digital Signature Algorithm keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const pair = sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.k256);
  let publicKey = pair.pub.get();
  publicKey = sjcl.codec.base64.fromBits(publicKey.x.concat(publicKey.y))
  let secretKey = pair.sec.get();
  secretKey = sjcl.codec.base64.fromBits(secretKey);
  const keypairObject = {
    pub: publicKey,
    sec : secretKey,
  }
  return keypairObject; // keypairObject.sec and keypairObject.pub are keys
};

export function signWithECDSA(privateKey, message) {
  // returns signature of message with privateKey
  // privateKey should be pair.sec from generateECDSA
  // message is a string
  // signature returned as a hex-encoded string
  const rawSecKey = new sjcl.ecc.ecdsa.secretKey(sjcl.ecc.curves.k256, sjcl.ecc.curves.k256.field.fromBits(sjcl.codec.base64.toBits(privateKey)));
  const bitarraySignature = rawSecKey.sign(sjcl.hash.sha256.hash(message));
  return utils.bitarrayToHex(bitarraySignature);
};
