#include <iostream>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

using namespace std;

bool encryptAES(const unsigned char *plainText, int plainTextLen, unsigned char *key, unsigned char *iv, unsigned char *cipherText) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error initializing cipher context" << endl;
        return false;
    }
    
    int len;
    int cipherTextLen;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error initializing AES encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen) != 1) {
        cerr << "Error during AES encryption update" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    cipherTextLen = len;

    if (EVP_EncryptFinal_ex(ctx, cipherText + len, &len) != 1) {
        cerr << "Error during AES encryption finalization" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return cipherTextLen;
}

bool decryptAES(const unsigned char *cipherText, int cipherTextLen, unsigned char *key, unsigned char *iv, unsigned char *decryptedText) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error initializing cipher context" << endl;
        return false;
    }
    
    int len;
    int decryptedTextLen;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error initializing AES decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, decryptedText, &len, cipherText, cipherTextLen) != 1) {
        cerr << "Error during AES decryption update" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    decryptedTextLen = len;

    if (EVP_DecryptFinal_ex(ctx, decryptedText + len, &len) != 1) {
        cerr << "Error during AES decryption finalization" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    decryptedTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return decryptedTextLen;
}

int main() {
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plainText[] = "AdvancedCyberSecData!";
    unsigned char cipherText[128];
    unsigned char decryptedText[128];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Error generating random key or IV" << endl;
        return 1;
    }

    cout << "Original Text: " << plainText << endl;

    int cipherTextLen = encryptAES(plainText, strlen((char*)plainText), key, iv, cipherText);
    if (!cipherTextLen) return 1;

    cout << "Encrypted Text now: ";
    for (int i = 0; i < cipherTextLen; i++) {
        cout << hex << setw(2) << setfill('0') << (int)cipherText[i];
    }
    cout << endl;

    int decryptedTextLen = decryptAES(cipherText, cipherTextLen, key, iv, decryptedText);
    if (!decryptedTextLen) return 1;

    decryptedText[decryptedTextLen] = '\0'; 
    cout << "Decrypted Text: " << decryptedText << endl;

    return 0;
}
