'use strict';

const ffi = require('ffi');
const ref = require('ref');

const G28147_KEYLEN = 32;
const SEANCE_VECTOR_LEN = 8;
const EXPORT_IMIT_SIZE = 4;

var ArrayType = require('ref-array');
var byte = ref.types.byte;
var ByteArray = ArrayType(byte);


const cryptoLib = ffi.Library('./libCrypto.so', {
	'CreateHash': ['string', ['string', 'int']],
	'Encrypt': [ByteArray, [ref.refType('int'), ref.refType('byte'), 'string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), ref.refType('byte'), ref.refType('int'), ref.refType('byte'), ref.refType('byte'), ref.refType('int')]],
	'Decrypt': ['string', ['string', 'string', ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), ref.refType('byte'), 'int', ref.refType('byte'), ref.refType('byte'), 'int']]
});


module.exports = {
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
				encryptionParam: encryptionParam.subarray(0, encryptionParamLength.deref())
			},
			IV: IV.subarray(0, IVLength.deref())
		};
    },
    decrypt: (encryptedBytes, responderContainerName, senderCertFilename, sessionKey, IV) => {
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
			sessionKey.encryptionParam.length
		);
		return encryptedBytes;
    }
};
