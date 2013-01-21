#include "utilities.h"

#define ALG             GCRY_CIPHER_AES256
#define SHA256          GCRY_MD_SHA256
#define MODE            GCRY_CIPHER_MODE_CBC
#define DEBUG           
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

size_t read_file(const char *filepath, char **buffer);

int initialize(gcry_cipher_hd_t *hd);

int encrypt(const gcry_cipher_hd_t hd, const char *plain_text, 
                const char *passphrase, struct message *msg);
int decrypt(const gcry_cipher_hd_t hd, const char *cipher_text, 
                const char *passphrase, struct message *msg);

int generate_iv(const gcry_cipher_hd_t hd, char **iv);
char* get_key_from_passphrase(const gcry_cipher_hd_t hd, 
                                const char *passphrase, const char *salt);

int serialize(const struct message *msg, const char *filepath);
int deserialize(const char *filepath, struct message *msg);
