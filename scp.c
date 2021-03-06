#include "scp.h"

int initialize(gcry_cipher_hd_t *hd)
{
    const char *version;
    gcry_error_t gcry_error;
    size_t key_len, block_len;
    
    if (!(version = gcry_check_version (GCRYPT_VERSION)))
    {
        printf("Unable to initialize subsystems\n");
        return 1;
    }

    #ifdef DEBUG
    printf("Using libgrypt version: %s\n", version);
    #endif

    // Initialization
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_ENABLE_M_GUARD, 0);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    gcry_control(GCRYCTL_SET_VERBOSITY, VERBOSITY_LVL);
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);

    if((gcry_error = gcry_cipher_open(hd, ALG, MODE, GCRY_CIPHER_CBC_CTS)))
    {
        print_gcry_error("Failed to create context handle", &gcry_error);
        return 1;
    }

    key_len = gcry_cipher_get_algo_keylen(ALG);
    block_len = gcry_cipher_get_algo_blklen(ALG);

    #ifdef DEBUG
    printf("Initialization complete\n");
    printf("Using %s algorithm with %zu key length and %zu block length in "  
           "%s mode\n",
            gcry_cipher_algo_name(ALG),
            key_len,
            block_len,
            get_str_cipher_mode(MODE));
    #endif

    return 0;
}

int encrypt(const gcry_cipher_hd_t hd, const char *plain_text, 
                const char *passphrase, struct message *msg)
{
    char *key;
    gcry_error_t gcry_error;
    size_t key_len, block_len;

    if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        printf("Libcrypt not initialized\n");
        return 1;
    }
    
    key_len = gcry_cipher_get_algo_keylen(ALG);
    block_len = gcry_cipher_get_algo_blklen(ALG);
  
    msg->salt = (char*)calloc(1, sizeof(char) * block_len);
    gcry_create_nonce(msg->salt, block_len);
    key = get_key_from_passphrase(hd, passphrase, msg->salt);

    // Set the key
    if((gcry_error = gcry_cipher_setkey(hd, key, key_len)))
    {
        print_gcry_error("Failed to set key", &gcry_error);
        return 1;
    }

    msg->iv = (unsigned char*)calloc(1, sizeof(unsigned char) * block_len);
    gcry_create_nonce(msg->iv, block_len);
    
    // Set the IV
    if((gcry_error = gcry_cipher_setiv(hd, msg->iv, block_len)))
    {
        print_gcry_error("Failed to set the IV", &gcry_error);
        return 1;
    }

    // Encrypt
    msg->text = (char*)calloc(1, msg->text_len);
    if((gcry_error = gcry_cipher_encrypt(hd, msg->text, msg->text_len, 
                                            plain_text, msg->text_len)))
    {
        print_gcry_error("Error encrypting", &gcry_error);

        free(msg->text);
        return 1;
    }

    msg->total_len = sizeof(msg->total_len) + sizeof(msg->filename_len) +          
                            msg->filename_len + msg->text_len + 
                            sizeof(msg->text_len) + block_len + block_len;

    // Generate the HMAC on the message
    msg->hmac = generate_hmac(key, key_len, msg);

    return 0;
}

int decrypt(const gcry_cipher_hd_t hd, const char *cipher_text, 
                const char *passphrase, struct message *msg)
{
    char *key, *plain_text;
    gcry_error_t gcry_error;
    size_t key_len, block_len;
    unsigned char *hmac;
    int hmac_OK = 0;
    FILE *fp;
    unsigned int digest_len;

    if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        printf("Libcrypt not initialized\n");
        return 1;
    }
    
    key_len = gcry_cipher_get_algo_keylen(ALG);
    block_len = gcry_cipher_get_algo_blklen(ALG);
    
    key = get_key_from_passphrase(hd, passphrase, msg->salt);
    digest_len = gcry_md_get_algo_dlen(SHA256);
    
    // Set the key
    if((gcry_error = gcry_cipher_setkey(hd, key, key_len)))
    {
        print_gcry_error("Failed to set key", &gcry_error);
        return 1;
    }

    // Set the IV
    if((gcry_error = gcry_cipher_setiv(hd, msg->iv, block_len)))
    {
        print_gcry_error("Failed to set the IV", &gcry_error);
        return 1;
    }
    
    msg->total_len = sizeof(msg->total_len) + sizeof(msg->filename_len) +          
                            msg->filename_len + msg->text_len + 
                            sizeof(msg->text_len) + block_len + block_len;

    // Generate the HMAC on the message
    hmac = generate_hmac(key, key_len, msg);

    printf("Comparing HMACs... : %s\n", 
            (hmac_OK = !memcmp(hmac, msg->hmac, digest_len)) == 1 ? 
                                        "OK" : "NOK");
    
    if(hmac_OK == 1)
    {
        // Decrypt
        plain_text = (char*)calloc(1, msg->text_len);
        if((gcry_error = gcry_cipher_decrypt(hd, plain_text, msg->text_len, 
                                            cipher_text, msg->text_len)))
        {
            print_gcry_error("Error decrypting", &gcry_error);
            free(plain_text);        
            return 1;
        }

        memcpy(msg->text, plain_text, msg->text_len);
    }

    return 0;
}

char* get_key_from_passphrase(const gcry_cipher_hd_t hd, 
                                const char *passphrase, const char *salt)
{
    char *key;
    gpg_error_t gpg_error;
    size_t key_len, salt_len, block_len;

    if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        printf("Libcrypt not initialized\n");
        return NULL;
    }

    key_len = gcry_cipher_get_algo_keylen(ALG);
    block_len = gcry_cipher_get_algo_blklen(ALG);

    // Generate the salt for PBKDF2
    salt_len = block_len;
    key = (char*)calloc(1, sizeof(char) * key_len);
    if((gpg_error = gcry_kdf_derive(
            passphrase, 
            strlen(passphrase), 
            GCRY_KDF_PBKDF2, 
            GCRY_MD_SHA1, 
            salt, 
            salt_len,
            4096, // No. of iteration 
            key_len,
            key)))
    {
        printf("Error deriving the key from the passphrase");
        free(key);
        return NULL;
    }

    return key;
}

unsigned char* generate_hmac(const char *key, const size_t key_len,
                                    const struct message *msg)
{
    unsigned char *hash, *ret_hash;
    gcry_error_t gcry_error;
    gcry_md_hd_t hd;
    unsigned int digest_len;
    size_t block_len;

    block_len = gcry_cipher_get_algo_blklen(ALG);
    digest_len = gcry_md_get_algo_dlen(SHA256);
    ret_hash = (unsigned char*)calloc(1, digest_len);

    if((gcry_error = gcry_md_open(&hd, SHA256, GCRY_MD_FLAG_HMAC)))
    {
        print_gcry_error("Cannot initialize SHA256 message digest", 
                            &gcry_error);
        return NULL;
    }

    gcry_md_enable(hd, SHA256);

    if((gcry_error = gcry_md_setkey(hd, key, key_len)))
    {
        print_gcry_error("Cannot set HMAC key", &gcry_error);
        return NULL;
    }

    // Write the key
    gcry_md_write(hd, key, key_len);
    
    // Write the message structure
    gcry_md_write(hd, &msg->total_len, sizeof(msg->total_len));
    gcry_md_write(hd, &msg->filename_len, sizeof(msg->filename_len));
    gcry_md_write(hd, msg->filename, msg->filename_len);
    gcry_md_write(hd, &msg->text_len, sizeof(msg->text_len));
    gcry_md_write(hd, msg->text, msg->text_len);
    gcry_md_write(hd, msg->iv, block_len);
    gcry_md_write(hd, msg->salt, block_len);

    #ifdef DEBUG
    // Print written meta data 
    printf("[%zu] [%zu] %s [%zu]\n", msg->total_len, msg->filename_len, 
            msg->filename, msg->text_len);
    #endif

    hash = gcry_md_read(hd, SHA256);
    memcpy(ret_hash, hash, digest_len);

    gcry_md_close(hd);
    
    #ifdef DEBUG
    printf("\nhash : ");
    print_hex(ret_hash, digest_len);
    printf("\n");
    #endif

    return ret_hash;
}
