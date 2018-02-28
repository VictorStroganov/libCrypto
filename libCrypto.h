#ifndef libCrypto_h__
#define libCrypto_h__

extern const char* CreateHash(const char* textToHash, int textToHashLength)

extern BYTE* Encrypt(DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, const char* senderContainerName, const char* responderCertFilename,  BYTE* textToEncrypt, int textToEncryptLength, BYTE* sessionEncryptedKey, BYTE* sessionSV, BYTE* IV, DWORD* IVLength, BYTE* sessionMacKey, BYTE* encryptionParam, DWORD* encryptionParamLength);

extern BYTE* Decrypt(const char* responderContainerName, const char* senderCertFilename, BYTE* encryptedText, int encryptedTextLength, BYTE* sessionEncryptedKey, BYTE* sessionSV, BYTE* IV, int IVLength, BYTE* sessionMacKey, BYTE* encryptionParam, int encryptionParamLength);

void HandleEncryptError(char *s);

#endif  // libCrypto_h__
