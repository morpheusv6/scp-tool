#include "utilities.h"

#define ALG             GCRY_CIPHER_AES256
#define SHA256          GCRY_MD_SHA256
#define MODE            GCRY_CIPHER_MODE_CBC
// Uncomment next line to view debug messages
//#define DEBUG           
#define VERBOSITY_LVL   4
#define MAX_BUF_LEN     1024

struct message
{
    size_t total_len;
    size_t filename_len;
    char *filename;
    size_t text_len;
    char *text;
    char *iv;
    char *salt;
    unsigned char *hmac;
};

/*
 * Initializes the gcrypt subsystems
 * Parameters:
 *  hd[output]: Context handle to subsequent calls
 * Return value:    0 if successful, 1 otherwise
 */
int initialize(gcry_cipher_hd_t *hd);

/* 
 * Encrypts the given plain text (including hmac generation)
 * Parameters:
 *  hd[input]:          Context handle 
 *  plain_text[input]:  Text to encrypt
 *  passphrase[input]:  Passphrase to generate the encryption key
 *  msg[input/output]:  Contains the encrypted plain text
 *                      As input, contains the filename and plain text length
 * Return value:    0 is successful, 1 otherwise
 */
int encrypt(const gcry_cipher_hd_t hd, const char *plain_text, 
                const char *passphrase, struct message *msg);
/* 
 * Decrypts the given cipher text (including hmac verification)
 * Parameters:
 *  hd[input]:          Context handle 
 *  cipher_text[input]: Text to decrypt
 *  passphrase[input]:  Passphrase to generate the decryption key
 *  msg[input/output]:  Contains the decrypted plain text
 *                      As input, contains the filename, iv, salt and cipher 
                        text length
 * Return value:    0 is successful, 1 otherwise
 */
int decrypt(const gcry_cipher_hd_t hd, const char *cipher_text, 
                const char *passphrase, struct message *msg);

/*
 * Generates the key from the passphrase and salt
 * Parameters:
 *  hd[input]:          Context handle
 *  passphrase[input]:  Passphrase to generate the key
 *  salt[input]:        Random value used in key generation
 * Return value:    Generated key is successful, NULL otherwise
 */
char* get_key_from_passphrase(const gcry_cipher_hd_t hd, 
                                const char *passphrase, const char *salt);

/*
 * Generates the message text
 * Parameters:
 *  key[input]:     Key used in the hmac generation
 *  key_len[input]: Length of the key
 *  msg[input]:     Contains the text
 * Return value:    Generated hmac is successful, NULL otherwise
 */
unsigned char* generate_hmac(const char *key, const size_t key_len,
                                const struct message *msg);
