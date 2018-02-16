'use strict';

const libCrypto = require('./libCrypto');

const textToEncode = "text message to encode";

const senderContainerName = "cplib"; //"sender-main"; 
const responderCertFilename =  "cplib.cer"; //"responder-main.cer"; //

const responderContainerName = "cplib"; //"responder-main"; 
const senderCertFilename = "cplib.cer"; //"sender-main.cer"; // 

const buffer = Buffer.from(textToEncode);

//Encrypt/Decrypt example
const bytesToEncrypt = new Uint8Array(buffer);

//let encryptionResult = libCrypto.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

//console.log("====KeyBlob:" + encryptionResult.sessionKeyBlob);

//let decryptedBytes = libCrypto.decrypt(encryptionResult.encryptedBytesArray, responderContainerName, senderCertFilename, encryptionResult.IV, encryptionResult.sessionKeyBlob);

const encBytesFromNet = new Uint8Array([42,131,141,63,42,192,17,95,199,13,27,119,61,178,126,51,144,15,194,102,221,7]);
const blobFromNET = new Uint8Array([1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,188,229,25,92,176,243,136,91,81,199,56,154,4,82,184,182,128,14,62,180,155,73,55,9,8,161,148,30,81,246,63,251,172,155,21,140,92,17,57,41,234,166,94,255,48,9,6,7,42,133,3,2,2,31,1]);
const IVfromNet = new Uint8Array([110,126,115,180,76,227,94,93]);

//[1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,
//	188,229,25,92,176,243,136,91,81,199,56,154,4,82,184,182,128,14,62,180,155,73,55,9,8,161,148,30,81,246,63,251,172,155,21,140,92,17,57,41,234,166,94,255,
//			48,9,6,7,42,133,3,2,2,31,1]

//[1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,
//	112,242,132,15,82,253,163,88,205,106,208,20,15,94,96,243,92,191,192,32,15,192,71,200,230,201,60,241,95,129,143,76,91,95,15,82,72,127,73,37,114,228,183,46,
//			48,9,6,7,42,133,3,2,2,31,1]

let decryptedBytes = libCrypto.decrypt(encBytesFromNet, "responder-main", "cert.cer", IVfromNet, blobFromNET);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);

//Signature example:
/*const bytesArrayToSign = new Uint8Array(buffer);
console.log("Bytes to sign:" + bytesArrayToSign);
const signatureResult = libCrypto.signHash(senderContainerName, bytesArrayToSign);
console.log("Signature:" + signatureResult.signature);
console.log("keyBlob:" + signatureResult.keyBlob + ":" + signatureResult.keyBlob.length);

const toVerify = new Uint8Array([3,179,235,2,14,161,13,255,243,182,221,123,67,93,94,180,69,157,171,168,39,143,199,92,219,127,252,37,48,85,90,113,119,182,63,195,4,197,209,194,154,165,49,105,140,26,175,193,122,51,41,48,247,99,39,44,160,59,155,211,246,195,87,34]);
const isVerified = libCrypto.verifySignature(bytesArrayToSign, signatureResult.signature, new Uint8Array(signatureResult.keyBlob.length), senderCertFilename);*/


//======CreateHash example:
// const hash = libCrypto.createHash(bytesArrayToSign);
// console.log("Hash:" + hash);