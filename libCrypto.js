'use strict';

const ffi = require('ffi');
const ref = require('ref');

const G28147_KEYLEN = 32;
const SEANCE_VECTOR_LEN = 8;
const EXPORT_IMIT_SIZE = 4;

const GOST3411_HASH_LENGTH = 32;

var ArrayType = require('ref-array');
var byte = ref.types.byte;
var ByteArray = ArrayType(byte);


const cryptoLib = ffi.Library('./libCrypto.so', {
	'CreateHash': ['void', [ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int')]],
	'Encrypt': [ByteArray, [ref.refType('int'), ref.refType('byte'), 'string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), ref.refType('byte'), ref.refType('int'), ref.refType('byte'), ref.refType('byte'), ref.refType('int')]],
	'Decrypt': ['string', ['string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), 'int', ref.refType('byte'), 'int']],
	'SignHash': ['void', ['string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('int'), ref.refType('byte'), ref.refType('int')]],
	'VerifySignature': ['bool', [ref.refType('byte'), 'int', ref.refType('byte'), 'int', ref.refType('byte'), 'int', 'string']]
});


module.exports = {
	createHash: (bytesArrayToHash) => {
		let hashLength = ref.alloc('int');
		let hash = new Uint8Array(GOST3411_HASH_LENGTH);

		cryptoLib.CreateHash(bytesArrayToHash, bytesArrayToHash.length, hash, hashLength);

		return hash.subarray(0, hashLength.deref());
	},
    encrypt: (bytesArrayToEncrypt, senderContainerName, responderCertFilename) => {
		let sessionEncryptedKey = new Uint8Array( G28147_KEYLEN );
		let sessionSV = new Uint8Array( SEANCE_VECTOR_LEN );
		let IV = new Uint8Array(100);
		let IVLength = ref.alloc('int');
		let sessionMacKey = new Uint8Array( EXPORT_IMIT_SIZE );
		let encryptionParam = new Uint8Array(200);
		let encryptionParamLength = ref.alloc('int');

		let sessionKeyBlobLength = ref.alloc('int');
		let sessionKeyBlob = new Uint8Array(200);

		const encrypted = cryptoLib.Encrypt(
			sessionKeyBlobLength, 
			sessionKeyBlob, 
			senderContainerName, 
			responderCertFilename, 
			bytesArrayToEncrypt, bytesArrayToEncrypt.length, 
			sessionEncryptedKey, 
			sessionSV, 
			IV, IVLength, 
			sessionMacKey, 
			encryptionParam, encryptionParamLength
		);

		return {
			encryptedBytesArray: bytesArrayToEncrypt,
			sessionKey: {
				sessionEncryptedKey: sessionEncryptedKey,
				sessionSV: sessionSV,
				sessionMacKey: sessionMacKey,
				encryptionParam: encryptionParam.subarray(0, encryptionParamLength.deref()),
				sessionKeyBlob: sessionKeyBlob.subarray(0, sessionKeyBlobLength.deref())
			},
			IV: IV.subarray(0, IVLength.deref())
		};
    },
    decrypt: (encryptedBytes, responderContainerName, senderCertFilename, sessionKey, IV, keyBlob) => {
		const decrypted = cryptoLib.Decrypt(
			responderContainerName,
			senderCertFilename,
			encryptedBytes, 
			encryptedBytes.length,
			sessionKey.sessionEncryptedKey,
			sessionKey.sessionSV,
			IV, 
			IV.length,
			sessionKey.sessionMacKey, 
			sessionKey.encryptionParam, 
			sessionKey.encryptionParam.length,
			keyBlob,
			keyBlob.length
		);
		return encryptedBytes;
    },
	signHash: (keyContainerName, messageBytesArray) => {
		let signatureBytesArrayLength = ref.alloc('int');
		let signatureBytesArray = new Uint8Array(2000);

		let pbKeyBlob = new Uint8Array(2000);
		let pbKeyBlobLength = ref.alloc('int');

    	cryptoLib.SignHash(keyContainerName, messageBytesArray, messageBytesArray.length, signatureBytesArray, signatureBytesArrayLength, pbKeyBlob, pbKeyBlobLength);
    	
    	return {
    		signature: signatureBytesArray.subarray(0, signatureBytesArrayLength.deref()),
    		keyBlob: pbKeyBlob.subarray(0, pbKeyBlobLength.deref())
    	};
    },
    verifySignature: (messageBytesArray, signatureBytesArray, keyBlob, certFilename) => {
    	return cryptoLib.VerifySignature(messageBytesArray, messageBytesArray.length, signatureBytesArray, signatureBytesArray.length, keyBlob, keyBlob.length, certFilename);
    }
};
