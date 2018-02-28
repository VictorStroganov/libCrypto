#include <stdio.h>
#include <string.h>
 
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>

#define BUFSIZE 1024
#define GR3411LEN  32//64

#define MAX_PUBLICKEYBLOB_SIZE 200

static HCRYPTPROV hProv = 0;		// Дескриптор CSP 
static HCRYPTKEY hKey = 0;		// Дескриптор закрытого ключа 
static HCRYPTKEY hSessionKey = 0;	// Дескриптор сессионного ключа
static HCRYPTKEY hAgreeKey = 0;        // Дескриптор ключа согласования

static HCRYPTHASH hHash = 0;
static HCRYPTKEY hPubKey = 0;
static BYTE *pbHash = NULL;
static BYTE *pbSignature = NULL;
static BYTE *pbKeyBlob = NULL; 

static FILE *certf=NULL;		// Файл, в котором хранится сертификат
static FILE *publicf=NULL;		// Файл, в котором хранится открытый ключ

static BYTE *pbKeyBlobSimple = NULL;   // Указатель на сессионный ключевой BLOB 
static BYTE *pbIV = NULL;		// Вектор инициализации сессионного ключа

void HandleError(const char *s);
void CleanUp(void);
void LoadPublicKey(BYTE *pbBlob, DWORD *pcbBlob, const char *szCertFile, const char *szKeyFile);

void SignHash(
    const char* keyContainer, 
    BYTE* messageBytesArray, 
    DWORD messageBytesArrayLength, 
    BYTE* signatureBytesArray, 
    DWORD* signatureBytesArrayLength
) {
    DWORD dwSigLen;
    DWORD dwBlobLen;
    DWORD cbHash;

    // Получение дескриптора контекста криптографического провайдера.
    if(CryptAcquireContext(
        &hProv, 
        keyContainer, 
        NULL, 
        PROV_GOST_2012_256, //PROV_GOST_2001_DH, 
        0)
    ) {
        printf("CSP context acquired.\n");
    }
    else {
        HandleError("Error during CryptAcquireContext.");
    }

    //--------------------------------------------------------------------
    // Получение открытого ключа подписи. Этот открытый ключ будет 
    // использоваться получателем хеша для проверки подписи.
    // В случае, когда получатель имеет доступ к открытому ключю
    // отправителя с помощью сертификата, этот шаг не нужен.

/*    if(CryptGetUserKey(   
        hProv,    
        AT_KEYEXCHANGE,    
        &hKey)
    ) {
        printf("The signature key has been acquired. \n");
    }
    else {
        HandleError("Error during CryptGetUserKey for signkey.");
    }

    //--------------------------------------------------------------------
    // Экпорт открытого ключа. Здесь открытый ключ экспортируется в 
    // PUBLICKEYBOLB для того, чтобы получатель подписанного хеша мог 
    // проверить подпись. Этот BLOB может быть записан в файл и передан
    // другому пользователю.

    if(CryptExportKey(   
        hKey,    
        0,    
        PUBLICKEYBLOB,
        0,    
        NULL, 
        &dwBlobLen)
    ) {
        printf("Size of the BLOB for the public key determined. \n");
    }
    else {
        HandleError("Error computing BLOB length.");
    }

    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    
    if(!pbKeyBlob) 
        HandleError("Out of memory. \n");

    // Сам экспорт в ключевой BLOB.
    if(CryptExportKey(   
        hKey, 
        0,    
        PUBLICKEYBLOB,    
        0,    
        pbKeyBlob,    
        &dwBlobLen)
    ) {
        printf("Contents have been written to the BLOB. \n");
    } else {
        HandleError("Error during CryptExportKey.");
    }
*/
    //--------------------------------------------------------------------
    // Создание объекта функции хеширования.
    if(CryptCreateHash(
        hProv, 
        CALG_GR3411_2012_256, //CALG_GR3411,
        0, 
        0, 
        &hHash)
    ) {
        printf("Hash object created. \n");
    } else {
        HandleError("Error during CryptCreateHash.");
    }

    //--------------------------------------------------------------------
    // Передача параметра HP_OID объекта функции хеширования.
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    // Определение размера BLOBа и распределение памяти.

    if(CryptGetHashParam(hHash,
        HP_OID,
        NULL,
        &cbHash,
        0)
    ) {
        printf("Size of the BLOB determined. \n");
    } else {
        HandleError("Error computing BLOB length.");
    }

    pbHash = (BYTE*)malloc(cbHash);
    if(!pbHash) 
       HandleError("Out of memory. \n");

    // Копирование параметра HP_OID в pbHash.
    if(CryptGetHashParam(hHash,
        HP_OID,
        pbHash,
        &cbHash,
        0)
    ) {
        printf("Parameters have been written to the pbHash. \n");
    } else {
        HandleError("Error during CryptGetHashParam.");
    }

    //--------------------------------------------------------------------
    // Вычисление криптографического хеша буфера.
    if(CryptHashData(
        hHash, 
        messageBytesArray, 
        messageBytesArrayLength, 
        0)
    ) {
        printf("The data buffer has been hashed.\n");
    } else {
        HandleError("Error during CryptHashData.");
    }

    // Определение размера подписи и распределение памяти.
    dwSigLen = 0;
    if(CryptSignHash(
        hHash, 
        AT_KEYEXCHANGE, 
        NULL, 
        0, 
        NULL, 
        &dwSigLen)
    ) {
        printf("Signature length %d found.\n", dwSigLen);
    } else {
        HandleError("Error during CryptSignHash.");
    }

    //--------------------------------------------------------------------
    // Распределение памяти под буфер подписи.
    pbSignature = (BYTE *)malloc(dwSigLen);
    if(!pbSignature)
        HandleError("Out of memory.");

    // Подпись объекта функции хеширования.
    if(CryptSignHash(
        hHash, 
        AT_KEYEXCHANGE, 
        NULL, 
        0, 
        pbSignature, 
        &dwSigLen)
    ) {
        printf("pbSignature is the hash signature.\n");
    } else {
        HandleError("Error during CryptSignHash.");
    }
    
    memcpy(signatureBytesArray, pbSignature, dwSigLen);
    memcpy(signatureBytesArrayLength, &dwSigLen, sizeof(dwSigLen));


    // Уничтожение объекта функции хеширования.
    if(hHash) 
        CryptDestroyHash(hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing is completed.\n\n");
}

BOOL VerifySignature(
    BYTE* messageBytesArray, DWORD messageBytesArrayLength, 
    BYTE* signatureByteArray, DWORD signatureBytesArrayLength,
    const char* certFilename
) {
    BOOL verificationResult = FALSE;
    BYTE  *pbKeyBlob = (BYTE *)malloc(MAX_PUBLICKEYBLOB_SIZE);
    DWORD pbKeyBlobLength = MAX_PUBLICKEYBLOB_SIZE;


    // Содержимое буфера pbBuffer представляет из себя некоторые 
    // подписанные ранее данные.
    BYTE *pbBuffer= (BYTE *)malloc(messageBytesArrayLength);
    memcpy(pbBuffer, messageBytesArray, messageBytesArrayLength);

    DWORD dwBufferLen = messageBytesArrayLength;

    LoadPublicKey(pbKeyBlob, &pbKeyBlobLength, certFilename, certFilename);

    //--------------------------------------------------------------------
    // Получение откытого ключа пользователя, который создал цифровую подпись, 
    // и импортирование его в CSP с помощью функции CryptImportKey. Она 
    // возвращает дескриптор открытого ключа в hPubKey.
    if(CryptImportKey(
        hProv,
        pbKeyBlob,
        pbKeyBlobLength,
        0,
        0,
        &hPubKey)
    ) {
        printf("The key has been imported.\n");
    } else {
        HandleError("Public key import failed.");
    }

    //--------------------------------------------------------------------
    // Создание нового объекта функции хеширования.
    if(CryptCreateHash(
        hProv, 
        CALG_GR3411_2012_256, //CALG_GR3411, //
        0, 
        0, 
        &hHash)
    ) {
        printf("The hash object has been recreated. \n");
    } else {
        HandleError("Error during CryptCreateHash.");
    }

    //--------------------------------------------------------------------
    // Вычисление криптографического хеша буфера.
    if(CryptHashData(
        hHash, 
        pbBuffer, 
        dwBufferLen, 
        0)
    ) {
        printf("The new has been created.\n");
    } else {
        HandleError("Error during CryptHashData.");
    }

    //--------------------------------------------------------------------
    // Проверка цифровой подписи.
    if(CryptVerifySignature(
        hHash, 
        signatureByteArray, 
        signatureBytesArrayLength, 
        hPubKey,
        NULL, 
        0)
    ) {
        printf("The signature has been verified.\n");
        verificationResult = TRUE;
    } else {
        printf("Signature not validated!\n");
        verificationResult = FALSE;
    }

    CleanUp();
    return verificationResult;
}

void CleanUp(void) {
    if(certf)
	   fclose (certf);

    if(publicf)
        fclose (publicf);

    if(hKey)
	   CryptDestroyKey(hKey);

    if(hSessionKey)
	   CryptDestroyKey(hSessionKey);

    if(hAgreeKey)
	   CryptDestroyKey(hAgreeKey);

    if(hProv) 
    	CryptReleaseContext(hProv, 0);

    if(pbKeyBlobSimple)
	   free(pbKeyBlobSimple);

    if(pbIV)
	   free(pbIV);
}

void HandleError(const char *s) {
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if(!err) 
        err = 1;
    exit(err);
}

void LoadPublicKey(BYTE *pbBlob, DWORD *pcbBlob, const char *szCertFile, const char *szKeyFile) {
    //if(fopen_s(&certf, szCertFile, "r+b" ))
    if((certf = fopen(szCertFile, "rb"))) {
        DWORD cbCert = 2000;
        BYTE  pbCert[2000];
        PCCERT_CONTEXT pCertContext = NULL;
        HCRYPTKEY hPubKey;
        printf( "The file '%s' was opened\n", szCertFile );

        cbCert = (DWORD)fread(pbCert, 1, cbCert, certf);
        if(!cbCert)
            HandleError( "Failed to read certificate\n" );
        printf( "Certificate was read from the '%s'\n", szCertFile );

        pCertContext = CertCreateCertificateContext (
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCert, cbCert);
        if (!pCertContext) {
            HandleError( "CertCreateCertificateContext" );
        }

        // Импортируем открытый ключ
        if (CryptImportPublicKeyInfoEx(hProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &(pCertContext->pCertInfo->SubjectPublicKeyInfo), 0, 0, NULL, &hPubKey)) {
            printf("Public key imported from cert file\n");
        } else {
            CertFreeCertificateContext(pCertContext);
            HandleError( "CryptImportPublicKeyInfoEx" );
        }
        CertFreeCertificateContext(pCertContext);
        
        // Экспортируем его в BLOB
        if (CryptExportKey(hPubKey, 0, PUBLICKEYBLOB, 0, pbBlob, pcbBlob)) {
            printf("Public key exported to blob\n");
        } else {
            HandleError( "CryptExportKey" );
        }
    } else {
        // Открытие файла, в котором содержится открытый ключ получателя.
        //if(!fopen_s(&publicf, szKeyFile, "r+b" ))
        if(!(publicf = fopen(szKeyFile, "rb")))
            HandleError( "Problem opening the public key blob file\n" );
        printf( "The file '%s' was opened\n", szKeyFile );

        *pcbBlob = (DWORD)fread(pbBlob, 1, *pcbBlob, publicf);
        if(!*pcbBlob)
            HandleError( "Failed to read key blob file\n" );
        printf( "Key blob was read from the '%s'\n", szKeyFile );
    }
}

void Encrypt(
    DWORD* sessionKeyBlobLength, BYTE* sessionKeyBlob, 
    const char* senderContainerName, 
    const char* responderCertFilename, 
    BYTE* textToEncrypt, 
    int textToEncryptLength, 
    BYTE* sessionEncryptedKey, 
    BYTE* sessionSV, 
    BYTE* IV, 
    DWORD* IVLength, 
    BYTE* sessionMacKey, 
    BYTE* encryptionParam, 
    DWORD* encryptionParamLength
    ) {
    BYTE  pbResponderKeyBlob[MAX_PUBLICKEYBLOB_SIZE];
    DWORD dwResponderKeyBlobLen = MAX_PUBLICKEYBLOB_SIZE;
    DWORD dwBlobLenSimple;

    DWORD dwIV = 0;
    DWORD bufLen = 0;
    ALG_ID ke_alg = CALG_PRO12_EXPORT;
    DWORD cbEncryptionParamSetStandart;

    // Получение дескриптора контейнера получателя с именем senderContainerName, 
    // находящегося в рамках провайдера. 
    if(CryptAcquireContext(&hProv, senderContainerName, NULL, PROV_GOST_2012_256/*PROV_GOST_2001_DH*/, 0)) {
	   printf("The key container \"%s\" has been acquired. \n", senderContainerName);
    } else {
	   HandleError("Error during CryptAcquireContext.");
    }

    LoadPublicKey(pbResponderKeyBlob, &dwResponderKeyBlobLen, responderCertFilename, responderCertFilename);

    // Получение дескриптора закрытого ключа отправителя.
    if(CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
        printf("The private key has been acquired. \n");
    } else {
	   HandleError("Error during CryptGetUserKey private key.");
    }

    // Получение ключа согласования импортом открытого ключа получателя
    // на закрытом ключе отправителя.
    if(CryptImportKey(hProv, pbResponderKeyBlob, dwResponderKeyBlobLen, hKey, 0, &hAgreeKey)) {
	   printf("The responder public key has been imported. \n");
    } else {
	   HandleError("Error during CryptImportKey public key.");
    }

    // Установление PRO12_EXPORT алгоритма ключа согласования
    if(CryptSetKeyParam(hAgreeKey, KP_ALGID, (LPBYTE)&ke_alg, 0)) {
	   printf("PRO12_EXPORT agree key algorithm has been set. \n");
    } else {
	   HandleError("Error during CryptSetKeyParam agree key.");
    }

/*    if(CryptSetKeyParam(hAgreeKey, KP_IV, UKM, 0)) {
       printf("UKM has been set. \n");
    } else {
       HandleError("Error during CryptSetKeyParam UKM agree key.");
    }*/


    // Генерация сессионного ключа.
    if(CryptGenKey(hProv, CALG_G28147, CRYPT_EXPORTABLE, &hSessionKey)) {
	   printf("Original session key is created. \n");
    } else {
	   HandleError("ERROR -- CryptGenKey.");
    }

     //--------------------------------------------------------------------
    // Зашифрование сессионного ключа.
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    // Определение размера BLOBа сессионного ключа и распределение памяти.
    if(CryptExportKey( hSessionKey, hAgreeKey, SIMPLEBLOB, 0, NULL, &dwBlobLenSimple)) {
	   printf("Size of the BLOB for the sender session key determined. \n");
    } else {
	   HandleError("Error computing BLOB length.");
    }

    pbKeyBlobSimple = (BYTE*)malloc(dwBlobLenSimple);

    if(!pbKeyBlobSimple) 
	   HandleError("Out of memory. \n");

    // Зашифрование сессионного ключа на ключе Agree.
    if(CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, pbKeyBlobSimple, &dwBlobLenSimple)) {
    	printf("Contents have been written to the BLOB. \n");
    } else {
	   HandleError("Error during CryptExportKey.");
    }

    // Определение размера вектора инициализации сессионного ключа. 
    if(CryptGetKeyParam(hSessionKey, KP_IV, NULL, &dwIV, 0)) {
	   printf("Size of the IV for the session key determined. \n");
    } else {
	   HandleError("Error computing IV length.");
    }

    pbIV = (BYTE*)malloc(dwIV);
    if (!pbIV)
	   HandleError("Out of memory. \n");
    
    // Определение вектора инициализации сессионного ключа.
    if(CryptGetKeyParam(hSessionKey, KP_IV, pbIV, &dwIV, 0)) {
	   printf( "CryptGetKeyParam succeeded. \n");
    } else {
	   HandleError("Error during CryptGetKeyParam.");
    }

    memcpy(IV, pbIV, dwIV);
    memcpy(IVLength, &dwIV, sizeof(dwIV));
    memcpy(sessionSV, ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bSV, SEANCE_VECTOR_LEN);
    memcpy(sessionEncryptedKey, ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptedKey, G28147_KEYLEN);
    memcpy(sessionMacKey, ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bMacKey, EXPORT_IMIT_SIZE);

    if (((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet[0] != 0x30)
    	HandleError("The EncryptionParam can not be written to the 'EncryptionParam.bin' - first byte is not 0x30\n");
    //CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_NAME, );
    cbEncryptionParamSetStandart = (DWORD)((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet[1] + sizeof((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet[0] + sizeof((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet[1];

    memcpy(encryptionParam, ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet, cbEncryptionParamSetStandart);
    memcpy(encryptionParamLength, &cbEncryptionParamSetStandart, sizeof(cbEncryptionParamSetStandart));

    memcpy(sessionKeyBlob, pbKeyBlobSimple, dwBlobLenSimple); //sizeof(pbKeyBlobSimple)
    memcpy(sessionKeyBlobLength, &dwBlobLenSimple, sizeof(dwBlobLenSimple));

    BOOL bFinal = TRUE;
    bufLen = textToEncryptLength;

    if(CryptEncrypt(hSessionKey, 0, bFinal, 0, textToEncrypt, &textToEncryptLength, bufLen)) {
        printf( "Encryption succeeded. \n");
    } else {
        HandleError("Encryption failed.");
    }

    CleanUp();
}

void Decrypt(
    const char* responderContainerName, 
    const char* senderCertFilename, 
    BYTE* encryptedText, int encryptedTextLength, 
    BYTE* sessionEncryptedKey, 
    BYTE* sessionSV, 
    BYTE* IV, int IVLength, 
    BYTE* sessionMacKey, 
    BYTE* encryptionParam, int encryptionParamLength,
    BYTE* keySimpleBlob, int keySimpleBlobLength
) {
    BYTE  pbKeyBlob[MAX_PUBLICKEYBLOB_SIZE];
    DWORD dwBlobLen = MAX_PUBLICKEYBLOB_SIZE;

    DWORD cbContent = 0;
    
    ALG_ID ke_alg = CALG_PRO12_EXPORT;

   // Получение дескриптора контейнера получателя с именем "responderContainerName", 
    // находящегося в рамках провайдера. 
    if(!CryptAcquireContext(&hProv, responderContainerName, NULL, PROV_GOST_2012_256/*PROV_GOST_2001_DH*/, 0)) {
	   HandleError("Error during CryptAcquireContext");
    }
    printf("The key container \"%s\" has been acquired. \n", responderContainerName);

/*
    BYTE *pbEncryptionParamSetStandart;
    DWORD cbEncryptionParamSetStandart;

    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeaderStandart;

    DWORD cbBlobLenSimple;

    tSimpleBlobHeaderStandart.BlobHeader.aiKeyAlg = CALG_G28147;
    tSimpleBlobHeaderStandart.BlobHeader.bType = SIMPLEBLOB;
    tSimpleBlobHeaderStandart.BlobHeader.bVersion = BLOB_VERSION;
    tSimpleBlobHeaderStandart.BlobHeader.reserved = 0;
    tSimpleBlobHeaderStandart.EncryptKeyAlgId = CALG_G28147;
    tSimpleBlobHeaderStandart.Magic = G28147_MAGIC;


    cbEncryptionParamSetStandart = encryptionParamLength;
    
    // allocate memory to contain the whole file:
    pbEncryptionParamSetStandart = (BYTE*)malloc(cbEncryptionParamSetStandart);
    if (pbEncryptionParamSetStandart == NULL)
	   HandleError("Out of memory. \n");
    
    memcpy(pbEncryptionParamSetStandart, encryptionParam, cbEncryptionParamSetStandart);


    cbBlobLenSimple = cbEncryptionParamSetStandart;
    cbBlobLenSimple += (sizeof(CRYPT_SIMPLEBLOB_HEADER) + SEANCE_VECTOR_LEN + G28147_KEYLEN + EXPORT_IMIT_SIZE);// +sizeof(pbEncryptionParamSetStandart);

    pbKeyBlobSimple = malloc(cbBlobLenSimple);

    if(!pbKeyBlobSimple)
	   HandleError("Out of memory. \n");

printf("cbBlobLenSimple: %d\n", cbBlobLenSimple);

    memcpy(&((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->tSimpleBlobHeader, &tSimpleBlobHeaderStandart, sizeof(CRYPT_SIMPLEBLOB_HEADER));
    memcpy( ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bSV, sessionSV, SEANCE_VECTOR_LEN );
    memcpy( ((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptedKey, sessionEncryptedKey, G28147_KEYLEN );

    memcpy(((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bEncryptionParamSet, pbEncryptionParamSetStandart, cbEncryptionParamSetStandart);

    memcpy(((CRYPT_SIMPLEBLOB*)pbKeyBlobSimple)->bMacKey, sessionMacKey, EXPORT_IMIT_SIZE);
*/

    LoadPublicKey(pbKeyBlob, &dwBlobLen, senderCertFilename, senderCertFilename);

    if(CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		printf("The private key has been acquired. \n");
    } else {
		HandleError("Error during CryptGetUserKey private key.");
    }

    if(CryptImportKey(hProv, pbKeyBlob, dwBlobLen, hKey, 0, &hAgreeKey)) {
		printf("The sender public key has been imported. \n");
    } else {
		HandleError("Error during CryptImportKey public key.");
    }

    if(CryptSetKeyParam(hAgreeKey, KP_ALGID, (LPBYTE)&ke_alg, 0)) {
		printf("PRO12_EXPORT agree key algorithm has been set. \n");
    } else {
		HandleError("Error during CryptSetKeyParam agree key.");
    }

 /*   if(CryptSetKeyParam(hAgreeKey, KP_IV, UKM, 0)) {
       printf("UKM has been set. \n");
    } else {
       HandleError("Error during CryptSetKeyParam UKM agree key.");
    }   */ 

    if(CryptImportKey(hProv, keySimpleBlob, keySimpleBlobLength, hAgreeKey, 0, &hSessionKey)) {
		printf("The session key has been imported. \n");
    } else {
		HandleError("Error during CryptImportKey session key.");
    }

    if(!CryptSetKeyParam(hSessionKey, KP_IV, IV, 0)) {
		HandleError("Error during CryptSetKeyParam.");
    }
    printf( "CryptSetKeyParam succeeded. \n");


    cbContent = (DWORD)encryptedTextLength;
	BYTE* pbContent = (BYTE*)malloc(encryptedTextLength); 
    memcpy(pbContent, encryptedText, encryptedTextLength);

    BOOL bFinal = TRUE;

    if(CryptDecrypt(hSessionKey, 0, bFinal, 0, pbContent, &cbContent)) {
		printf( "Decryption succeeded. \n");
    } else {
		HandleError("Decryption failed.");
    }
    
    memcpy(encryptedText, pbContent, cbContent);
    printf("The program ran to completion without error. \n");

 //  CleanUp();
  //  free(pbEncryptionParamSetStandart);
}

void CreateHash(BYTE* bytesArrayToHash, DWORD bytesArrayToHashLength, BYTE* hash, DWORD* hashLength) {
   	HCRYPTPROV hProv = 0;
   	HCRYPTHASH hHash = 0;

	BYTE rgbHash[GR3411LEN];
    DWORD cbHash = GR3411LEN;

	if(!CryptAcquireContext(
		&hProv,
		NULL,
		NULL,
		PROV_GOST_2012_256, //PROV_GOST_2001_DH,
		CRYPT_VERIFYCONTEXT)) {
		HandleError("CryptAcquireContext failed");
	}

	if(!CryptCreateHash(hProv, /*CALG_GR3411*/CALG_GR3411_2012_256, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		HandleError("CryptCreateHash failed"); 
	}

	if(!CryptHashData(
        hHash,
        bytesArrayToHash,
        bytesArrayToHashLength,
        0))
    {
	    CryptReleaseContext(hProv, 0);
	    CryptDestroyHash(hHash);
	    HandleError("CryptHashData failed"); 
	}

    if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		HandleError("CryptGetHashParam failed"); 
	}

    memcpy(hash, rgbHash, cbHash);
    memcpy(hashLength, &cbHash, sizeof(cbHash));

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}