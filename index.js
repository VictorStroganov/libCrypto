'use strict';

const libCrypto = require('./libCrypto');

const textToEncode = "text message to encode";


const senderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e"; // "cert_tokarev_flash"; // "cplib"; //"sender-main"; 
const responderCertFilename =  "2012_Cert.cer"; // "tokarev_cer.cer"; //"cplib.cer"; //"responder-main.cer"; //

const responderContainerName = "5973e5bc6-1e43-6206-c603-21fdd08867e"; //"cert_tokarev_flash"; // "cplib"; //"responder-main"; 
const senderCertFilename = "2012_Cert.cer"; //"tokarev_cer.cer"; //"cplib.cer"; //"sender-main.cer"; // 


const buffer = Buffer.from(textToEncode);

//Encrypt/Decrypt example
const bytesToEncrypt = new Uint8Array(buffer);

let encryptionResult = libCrypto.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

console.log("====encryptedBytesArray:" + encryptionResult.encryptedBytesArray);

console.log("====KeyBlob:" + encryptionResult.sessionKey.sessionKeyBlob);
console.log("====sessionEncryptedKey:" + encryptionResult.sessionKey.sessionEncryptedKey);
console.log("====sessionSV:" + encryptionResult.sessionKey.sessionSV);
console.log("====sessionMacKey:" + encryptionResult.sessionKey.sessionMacKey);
console.log("====encryptionParam:" + encryptionResult.sessionKey.encryptionParam);

let decryptedBytes = libCrypto.decrypt(
	encryptionResult.encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	encryptionResult.sessionKey,
	encryptionResult.IV,
	encryptionResult.sessionKey.sessionKeyBlob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);



//Signature example:
//const bytesArrayToSign = new Uint8Array(buffer);
//console.log("Bytes to sign:" + bytesArrayToSign);


//const signature = libCrypto.signHash(senderContainerName, bytesArrayToSign);
//console.log("Signature:" + signature);

//const toVerify = new Uint8Array([199,4,32,149,176,37,73,113,113,176,34,45,100,149,210,122,153,11,6,240,245,90,241,167,178,123,223,32,129,23,14,192,204,223,163,100,159,237,34,253,69,82,41,243,90,201,86,35,201,61,118,76,245,21,38,198,86,60,251,142,238,144,190,223]);
//const isVerified = libCrypto.verifySignature(bytesArrayToSign, signature, senderCertFilename);


//======CreateHash example:
 //const hash = libCrypto.createHash(bytesArrayToSign);
 //console.log("Hash:" + hash);
