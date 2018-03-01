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
console.log("====Bytes to encode:" + bytesToEncrypt);

let encryptionResult = libCrypto.encrypt(bytesToEncrypt, senderContainerName, responderCertFilename);

console.log("====encryptedBytesArray:" + encryptionResult.encryptedBytesArray);

console.log("====KeyBlob:" + encryptionResult.sessionKey.sessionKeyBlob);
console.log("====sessionEncryptedKey:" + encryptionResult.sessionKey.sessionEncryptedKey);
console.log("====sessionSV:" + encryptionResult.sessionKey.sessionSV);
console.log("====sessionMacKey:" + encryptionResult.sessionKey.sessionMacKey);
console.log("====encryptionParam:" + encryptionResult.sessionKey.encryptionParam);
console.log("====IV:" + encryptionResult.IV);


let decryptedBytes = libCrypto.decrypt(
	encryptionResult.encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	encryptionResult.IV,
	encryptionResult.sessionKey.sessionKeyBlob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);

//------------node.js
/*
let encryptedBytesArray = new Uint8Array([129,146,107,228,193,8,195,73,157,245,216,41,116,168,236,82,208,125,113,17,178,252]);

let KeyBlob = new Uint8Array([
	//header: 16: 
	1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,
		//sessionSV: 8: 
		84,51,142,134,228,89,28,40,
			//sessionEncryptedKey: 32: 
			2,175,153,201,22,209,165,101,167,151,219,94,218,168,31,102,204,64,97,41,46,110,139,29,159,116,30,113,215,37,89,165,
				//sessionMacKey: 4: 
				138,58,159,111,
					//encryptionParam: 13: 
					48,11,6,9,42,133,3,7,1,2,5,1,1]);

let sessionSV = new Uint8Array([84,51,142,134,228,89,28,40]);

let sessionEncryptedKey = new Uint8Array([2,175,153,201,22,209,165,101,167,151,219,94,218,168,31,102,204,64,97,41,46,110,139,29,159,116,30,113,215,37,89,165]);

let sessionMacKey = new Uint8Array([138,58,159,111]);

let encryptionParam = new Uint8Array([48,11,6,9,42,133,3,7,1,2,5,1,1]);
*/
//-------------------CryptoProKeyWrap
/*
let encryptedBytesArray = new Uint8Array([76,149,16,192,19,94,79,85,106,67,83,182,44,61,246,147,153,102,104,45,3,114]);

let blob = new Uint8Array([
1,32,0,0,30,102,0,0,253,81,74,55,30,102,0,0,
	140,29,137,127,121,245,125,179,
		77,89,113,132,96,50,150,35,226,43,47,186,238,169,235,137,27,58,69,127,189,139,248,2,237,223,247,82,179,202,92,119,12,24,18,44,
		48,9,6,7,42,133,3,2,2,31,1]);

let iv = new Uint8Array([59,133,22,139,66,152,166,35]);

let encryptedKey = new Uint8Array([77,89,113,132,96,50,150,35,226,43,47,186,238,169,235,137,27,58,69,127,189,139,248,2,237,223,247,82,179,202,92,119]);

let ParamSet = new Uint8Array([48,9,6,7,42,133,3,2,2,31,1]);//"1.2.643.2.2.31.1";

let Mac = new Uint8Array([12,24,18,44]);

let Ukm = new Uint8Array([140,29,137,127,121,245,125,179]);
//----------------------------------------
let decryptedBytes = libCrypto.decrypt(
	encryptedBytesArray, 
	responderContainerName,
	senderCertFilename,
	iv,
	blob);

const decryptedMessage = (new Buffer(decryptedBytes)).toString();
console.log("Decrypted message:" + decryptedMessage);
*/

//Signature example:
//const bytesArrayToSign = new Uint8Array(buffer);
//console.log("Bytes to sign:" + bytesArrayToSign);


//const signature = libCrypto.signHash(senderContainerName, bytesArrayToSign);
//console.log("Signature:" + signature);

//const toVerify = new Uint8Array([199,4,32,149,176,37,73,113,113,176,34,45,100,149,210,122,153,11,6,240,245,90,241,167,178,123,223,32,129,23,14,192,204,223,163,100,159,237,34,253,69,82,41,243,90,201,86,35,201,61,118,76,245,21,38,198,86,60,251,142,238,144,190,223]);
//const isVerified = libCrypto.verifySignature(bytesArrayToSign, signature, senderCertFilename);


//CreateHash example:
 //const hash = libCrypto.createHash(bytesArrayToSign);
 //console.log("Hash:" + hash);
