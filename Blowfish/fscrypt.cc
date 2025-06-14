#include <iostream>
#include <cstring>
#include <openssl/blowfish.h>

const int BLOCKSIZE = 8;
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen) {
    int padded_len = bufsize + (BLOCKSIZE - bufsize % BLOCKSIZE);
    char *padded_text = new char[padded_len];
    int pad_bytes = padded_len - bufsize;
    std::memcpy(padded_text, plaintext, bufsize);
    std::memset(padded_text + bufsize, pad_bytes, pad_bytes);  // Pad with pad length

    BF_KEY key;
    BF_set_key(&key, strlen(keystr), (unsigned char *)keystr);

    char *ciphertext = new char[padded_len];
    char iv[BLOCKSIZE] = {0};  // All zeros initialization vector

    for (int i = 0; i < padded_len; i += BLOCKSIZE) {
        BF_ecb_encrypt((unsigned char *)(padded_text + i), (unsigned char *)(ciphertext + i), &key, BF_ENCRYPT);
        // XOR with previous ciphertext block (implementing CBC mode)
        for (int j = 0; j < BLOCKSIZE; j++) {
            ciphertext[i + j] ^= iv[j];
        }
        std::memcpy(iv, ciphertext + i, BLOCKSIZE);  // Update IV for next block
    }

    delete[] padded_text;
    *resultlen = padded_len;
    return ciphertext;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen) {
    BF_KEY key;
    BF_set_key(&key, strlen(keystr), (unsigned char *)keystr);

    char *decrypted_text = new char[bufsize];
    char iv[BLOCKSIZE] = {0};  // All zeros initialization vector

    // Cast ciphertext to (unsigned char *) for pointer arithmetic
    unsigned char *ctext = (unsigned char *)ciphertext;

    for (int i = 0; i < bufsize; i += BLOCKSIZE) {
        // Work with unsigned char * for ciphertext
        for (int j = 0; j < BLOCKSIZE; j++) {
            unsigned char tmp = ctext[i + j];
            ctext[i + j] ^= iv[j];
            iv[j] = tmp;  // Update IV for next block
        }
        BF_ecb_encrypt(ctext + i, (unsigned char *)(decrypted_text + i), &key, BF_DECRYPT);
    }

    int pad_bytes = decrypted_text[bufsize - 1];
    *resultlen = bufsize - pad_bytes;
    return decrypted_text;
}