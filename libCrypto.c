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
#define GR3411LEN  64

#define MAX_PUBLICKEYBLOB_SIZE 200

static HCRYPTPROV hProv = 0;		// Дескриптор CSP 
static HCRYPTKEY hKey = 0;		// Дескриптор закрытого ключа 
static HCRYPTKEY hSessionKey = 0;	// Дескриптор сессионного ключа
static HCRYPTKEY hAgreeKey = 0;        // Дескриптор ключа согласования

static FILE *certf=NULL;		// Файл, в котором хранится сертификат
static FILE *publicf=NULL;		// Файл, в котором хранится открытый ключ
static FILE *EncryptionParam;           // Файл для хранения неменяемой части блоба

static BYTE *pbKeyBlobSimple = NULL;   // Указатель на сессионный ключевой BLOB 
static BYTE *pbIV = NULL;		// Вектор инициализации сессионного ключа


void CleanUp(void) {
    if(certf)
	   fclose (certf);

    if(publicf)
        fclose (publicf);

    if (EncryptionParam)
    	fclose(EncryptionParam);

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

void LoadPublicKey(BYTE *pbBlob, DWORD *pcbBlob, char *szCertFile, char *szKeyFile)
{
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

BYTE* Encrypt(
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
    
    BYTE  pbKeyBlob[MAX_PUBLICKEYBLOB_SIZE];
    DWORD dwBlobLen = MAX_PUBLICKEYBLOB_SIZE;
    DWORD dwBlobLenSimple;

    DWORD cbContent = 0;
    DWORD dwIV = 0;
    DWORD bufLen = 0;
    ALG_ID ke_alg = CALG_PRO12_EXPORT;
    DWORD cbEncryptionParamSetStandart;

    // Получение дескриптора контейнера получателя с именем senderContainerName, 
    // находящегося в рамках провайдера. 
    if(CryptAcquireContext(&hProv, senderContainerName, NULL, PROV_GOST_2012_256, 0)) {
	   printf("The key container \"%s\" has been acquired. \n", senderContainerName);
    } else {
	   HandleError("Error during CryptAcquireContext.");
    }

    LoadPublicKey(pbKeyBlob, &dwBlobLen, responderCertFilename, "Responder.pub");


    // Получение дескриптора закрытого ключа отправителя.
    if(CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
        printf("The private key has been acquired. \n");
    } else {
	   HandleError("Error during CryptGetUserKey private key.");
    }

    // Получение ключа согласования импортом открытого ключа получателя
    // на закрытом ключе отправителя.
    if(CryptImportKey(hProv, pbKeyBlob, dwBlobLen, hKey, 0, &hAgreeKey)) {
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

    printf("dwBlobLenSimple: %d\n", dwBlobLenSimple);

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

    cbContent = (DWORD)textToEncryptLength;
    BYTE* pbContent = textToEncrypt;
  
    BOOL bFinal = TRUE;
    bufLen = cbContent;

    if(CryptEncrypt(hSessionKey, 0, bFinal, 0, pbContent, &cbContent, bufLen)) {
        printf( "Encryption succeeded. \n");
    } else {
        HandleError("Encryption failed.");
    }

   	memcpy(textToEncrypt, pbContent, cbContent);

    CleanUp();

	return textToEncrypt;
}

BYTE* Decrypt(
    const char* responderContainerName, 
    const char* senderCertFilename, 
    BYTE* encryptedText, int encryptedTextLength, 
    BYTE* sessionEncryptedKey, 
    BYTE* sessionSV, 
    BYTE* IV, int IVLength, 
    BYTE* sessionMacKey, 
    BYTE* encryptionParam, int encryptionParamLength
) {
    BYTE  pbKeyBlob[MAX_PUBLICKEYBLOB_SIZE];
    DWORD dwBlobLen = MAX_PUBLICKEYBLOB_SIZE;
//    BYTE *pbKeyBlobSimple = NULL;
    DWORD cbBlobLenSimple;
//    BYTE pbIV[100];
    DWORD dwIV = 0;

    DWORD cbContent = 0;
    ALG_ID ke_alg = CALG_PRO12_EXPORT;
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeaderStandart;
    DWORD dwBytesRead;
    BYTE *pbEncryptionParamSetStandart;
    DWORD cbEncryptionParamSetStandart;

    tSimpleBlobHeaderStandart.BlobHeader.aiKeyAlg = CALG_G28147; 
    tSimpleBlobHeaderStandart.BlobHeader.bType = SIMPLEBLOB;
    tSimpleBlobHeaderStandart.BlobHeader.bVersion = BLOB_VERSION;
    tSimpleBlobHeaderStandart.BlobHeader.reserved = 0;
    tSimpleBlobHeaderStandart.EncryptKeyAlgId = CALG_G28147;
    tSimpleBlobHeaderStandart.Magic = G28147_MAGIC;    

    dwIV = IVLength;
    pbIV = (BYTE*)malloc(dwIV);
    memcpy(pbIV, IV, dwIV);

   // Получение дескриптора контейнера получателя с именем "responderContainerName", 
    // находящегося в рамках провайдера. 
    if(!CryptAcquireContext(&hProv, responderContainerName, NULL, PROV_GOST_2012_256, 0)) {
	   HandleError("Error during CryptAcquireContext");
    }
    printf("The key container \"%s\" has been acquired. \n", responderContainerName);

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


    LoadPublicKey(pbKeyBlob, &dwBlobLen, senderCertFilename, "Sender.pub");

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

    if(CryptImportKey(hProv, pbKeyBlobSimple, cbBlobLenSimple, hAgreeKey, 0, &hSessionKey)) {
		printf("The session key has been imported. \n");
    } else {
		HandleError("Error during CryptImportKey session key.");
    }

    if(!CryptSetKeyParam(hSessionKey, KP_IV, pbIV, 0)) {
		HandleError("Error during CryptSetKeyParam.");
    }
    printf( "CryptSetKeyParam succeeded. \n");


    cbContent = (DWORD)encryptedTextLength; //sizeof(encryptedText);
	BYTE* pbContent = (BYTE*)encryptedText;

    BOOL bFinal = TRUE; //feof(Encrypt);

    if(CryptDecrypt(hSessionKey, 0, bFinal, 0, pbContent, &cbContent)) {
		printf( "Decryption succeeded. \n");
    } else {
		HandleError("Decryption failed.");
    }
    
    memcpy(encryptedText, pbContent, cbContent);

    CleanUp();
    free(pbEncryptionParamSetStandart);

    printf("The program ran to completion without error. \n");
}

const char* CreateHash(const char* textToHash, int textToHashLength) {
   		HCRYPTPROV hProv = 0;
   		HCRYPTHASH hHash = 0;

		BYTE rgbHash[GR3411LEN];
    	DWORD cbHash = 0;

		CHAR rgbDigits[] = "0123456789abcdef";
		DWORD i;

		BYTE * bufferToHash = (BYTE*) textToHash;
		DWORD bufferToHashLength = (DWORD)textToHashLength;

		char resultHash[64];

		if(!CryptAcquireContext(
			&hProv,
			NULL,
			NULL,
			PROV_GOST_2012_256,
			CRYPT_VERIFYCONTEXT)) {
			HandleError("CryptAcquireContext failed");
		}

		if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash)) {
			CryptReleaseContext(hProv, 0);
			HandleError("CryptCreateHash failed"); 
		}

		if(!CryptHashData(
	            hHash,
	            bufferToHash,
	            bufferToHashLength,
	            0))
		{
		    CryptReleaseContext(hProv, 0);
		    CryptDestroyHash(hHash);
		    HandleError("CryptHashData failed"); 
		}

		cbHash = GR3411LEN;
   		if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			HandleError("CryptGetHashParam failed"); 
		}

	    for(i = 0; i < cbHash; i++) {
			sprintf(resultHash + i * 2, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
    	}

    	CryptDestroyHash(hHash);
    	CryptReleaseContext(hProv, 0);
		
		char * stringToReturn = malloc(sizeof(resultHash));
    	memcpy(stringToReturn, resultHash, sizeof(resultHash));
		
		return stringToReturn;
	}