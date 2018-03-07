#ifndef libCrypto_h__
#define libCrypto_h__

#define GR3411LEN  32//64

#define MAX_PUBLICKEYBLOB_SIZE 200

typedef struct CallResult {
    int status;
    DWORD errorCode;
    char *errorMessage;
} CallResult;

CallResult ResultSuccess() {
    CallResult result = {0, 0, ""};
    return result;
}

CallResult HandleError(const char *s);

CallResult LoadPublicKey(HCRYPTPROV hProv, BYTE *pbBlob, DWORD *pcbBlob, const char *szCertFile, const char *szKeyFile);

CallResult SignHash(
    const char* keyContainer, 
    BYTE* messageBytesArray, 
    DWORD messageBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength
);

CallResult VerifySignature(
    BYTE* messageBytesArray, DWORD messageBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    const char* certFilename,
    BOOL *verificationResultToReturn
);

CallResult Encrypt(
    DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, 
    const char* senderContainerName, 
    const char* responderCertFilename, 
    BYTE* textToEncrypt, 
    int textToEncryptLength, 
    BYTE* IV, 
    DWORD* IVLength
);

CallResult Decrypt(
    const char* responderContainerName, 
    const char* senderCertFilename, 
    BYTE* encryptedText, int encryptedTextLength, 
    BYTE* IV, int IVLength, 
    BYTE* keySimpleBlob, int keySimpleBlobLength
);

CallResult CreateHash(BYTE* bytesArrayToHash, DWORD bytesArrayToHashLength, BYTE* hash, DWORD* hashLength);

#endif  // libCrypto_h__
