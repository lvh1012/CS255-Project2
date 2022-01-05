"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  HMACWithSHA256,
  HMACWithSHA512,
  SHA256,
  SHA512,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateEG,
  computeDH,
  generateECDSA,
  signWithECDSA,
  verifyWithECDSA,
  randomHexString,
  hexStringSlice,
} from "./lib";

/********* Implementation ********/

const chain_constant = randomHexString(64);
const max_skip = 256;

/*
Returns a new Diffie-Hellman key pair
*/
function GENERATE_DH() {
  return generateEG();
}

/*
Returns the output from the Diffie-Hellman 
calculation between the private key from the 
DH key pair dh_pair and the DH public key dh_pub. 
If the DH function rejects invalid public keys, 
then this function may raise an exception 
which terminates processing.
*/
function DH(dh_pair, dh_pub) {
  return computeDH(dh_pair.sec, dh_pub);
}

/*
Returns a pair (32-byte root key, 32-byte chain key)
as the output of applying a KDF keyed by a 32-byte root key rk
to a Diffie-Hellman output dh_out.
*/
function KDF_RK(rk, dh_out) {
  var bytes64 = HMACWithSHA512(rk, dh_out);
  var bytes32_root = hexStringSlice(bytes64, 0, 256 - 1);
  var bytes32_chain = hexStringSlice(bytes64, 256, 512 - 1);
  return [bytes32_root, bytes32_chain];
}

/*
Returns a pair (32-byte chain key, 32-byte message key) 
as the output of applying a KDF keyed by a 32-byte chain key ck 
to some constant.
*/
function KDF_CK(ck) {
  var bytes64 = HMACWithSHA512(ck, chain_constant);
  var bytes32_chain = hexStringSlice(bytes64, 0, 256 - 1);
  var bytes32_message = hexStringSlice(bytes64, 256, 512 - 1);
  return [bytes32_chain, bytes32_message];
}

/*
Returns an AEAD encryption of plaintext with message key mk [5]. 
The associated_data is authenticated but is not included in the ciphertext. 
Because each message key is only used once, the AEAD nonce may handled 
in several ways: fixed to a constant; derived from mk alongside 
an independent AEAD encryption key; derived as an additional output 
from KDF_CK(); or chosen randomly and transmitted.
*/
function ENCRYPT(mk, plaintext, associated_data) {
  return encryptWithGCM(mk.slice(0, 32), plaintext, associated_data);
}

/*
Returns the AEAD decryption of ciphertext with message key mk. 
If authentication fails, an exception will be raised that 
terminates processing.
*/
function DECRYPT(mk, ciphertext, associated_data) {
  return decryptWithGCM(mk.slice(0, 32), ciphertext, associated_data);
}

/*
Creates a new message header containing the DH ratchet public key 
from the key pair in dh_pair, the previous chain length pn, 
and the message number n. The returned header object contains ratchet public key dh 
and integers pn and n.
*/
function HEADER(dh_pair, pn, n, mk, govPublicKey) {
  const dhGov = GENERATE_DH();
  const kGov = DH(dhGov, govPublicKey);

  return {
    pub: dh_pair.pub,
    previous_chain_length: pn,
    message_number: n,
    vGov: dhGov.pub,
    cGov: ENCRYPT(kGov, mk.slice(0, 32), null)
  };
}


function TrySkippedMessageKeys(state, header, ciphertext) {
    if (state.mkskipped[JSON.stringify([header.pub, header.message_number])] !== undefined){
        mk = state.mkskipped[JSON.stringify([header.pub, header.message_number])];
        delete state.mkskipped[JSON.stringify([header.pub, header.message_number])];
        return DECRYPT(mk, ciphertext, header);
    }
    else{
        return null
    }
}

function SkipMessageKeys(state, until) {
  if (state.nr + max_skip < until) throw Exception;
  if (state.ckr != null) {
    while (state.nr < until) {
      let mk;
      [state.ckr, mk] = KDF_CK(state.ckr);
      state.mkskipped[JSON.stringify([state.dhr, state.nr])] = mk;
      state.nr += 1;
    }
  }
}

function DHRatchet(state, header) {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = header.pub;
  [state.rk, state.ckr] = KDF_RK(state.rk, DH(state.dhs, state.dhr));
  state.dhs = GENERATE_DH();
  [state.rk, state.cks] = KDF_RK(state.rk, DH(state.dhs, state.dhr));
}

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.dhKeyPair = null;
  };

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  generateCertificate(username) {
    const { pub, sec } = GENERATE_DH();
    this.dhKeyPair = { pub, sec };
    const certificate = {
      username,
      pub
    };
    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  receiveCertificate(certificate, signature) {
    const { username, pub } = certificate;
    if (!verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature)) {
      throw "certificate is invalid";
    }
    this.certs[username] = certificate;
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  sendMessage(name, plaintext) {
    const receiverCertificate = this.certs[name];
    const receiverDHPublicKey = receiverCertificate.pub;
    const SK = DH(this.dhKeyPair, receiverDHPublicKey).slice(0, 32);
    if (!this.conns[name]) {
      const dhs = GENERATE_DH();
      const dhr = receiverDHPublicKey;
      const [rk, cks] = KDF_RK(SK, DH(dhs, dhr));
      this.conns[name] = {
        dhs,
        dhr,
        rk,
        cks,
        ckr: null,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: {}
      };
    }

    const state = this.conns[name];
    let mk;
    [state.cks, mk] = KDF_CK(state.cks);
    const header = HEADER(state.dhs, state.pn, state.ns, mk, this.govPublicKey);
    state.ns++;
    const ciphertext = ENCRYPT(mk, plaintext, JSON.stringify(header));
    return [header, ciphertext];
  }


  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  receiveMessage(name, [header, ciphertext]) {
    if (!this.conns[name]) {
      const senderCertificate = this.certs[name];
      const theirPublicKey = senderCertificate.pub;
      const SK = DH(this.dhKeyPair, theirPublicKey).slice(0, 32);
      const dhs = this.dhKeyPair;

      this.conns[name] = {
        dhs,
        dhr: null,
        rk: SK,
        cks: null,
        ckr: null,
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: {}
      };
    }

    const state = this.conns[name];
    let plaintext = TrySkippedMessageKeys(state, header, ciphertext);
    if (plaintext != null) {
      return plaintext;
    }
    if (header.pub !== state.dhr) {
      SkipMessageKeys(state, header.previous_chain_length);
      DHRatchet(state, header);
    }
    SkipMessageKeys(state, header.message_number);
    let mk;
    [state.ckr, mk] = KDF_CK(state.ckr);
    state.nr++;
    plaintext = DECRYPT(mk, ciphertext, JSON.stringify(header));
    return plaintext;
  }
};
