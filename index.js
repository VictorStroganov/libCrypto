'use strict';

const libCrypto = require('./libCrypto');

const textToEncode = "text message to encode";

const senderContainerName = "cplib";
const responderCertFilename = "cplib.cer";

const responderContainerName = "cplib";
const senderCertFilename = "cplib.cer";

//console.log( cryptoLib.CreateHash(textToEncode, textToEncode.length) );

const buffer = Buffer.from(textToEncode);

const bytesToEncrypt = new Uint8Array(buffer);

let encryptionResult = libCrypto.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

let decryptedBytes = libCrypto.decrypt(encryptionResult.encryptedBytesArray, responderContainerName, senderCertFilename, encryptionResult.sessionKey, encryptionResult.IV);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);

