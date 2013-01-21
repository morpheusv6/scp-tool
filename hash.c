#include "hash.h"

unsigned char* generate_hash(const char *key, const size_t key_len,
                                const struct message *msg)
{
    unsigned char *hash, *inner_hash;
    unsigned int digest_len;

    digest_len = gcry_md_get_algo_dlen(SHA256);

    // Create the hash in the format H(key || H(key || message))
    inner_hash = generate_inner_hash(key, key_len, msg);
    hash = generate_outer_hash(key, key_len, inner_hash, digest_len);

    return hash;
}

unsigned char* generate_inner_hash(const char *key, const size_t key_len,
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

    // Print written contents
    printf("[%zu] [%zu] %s [%zu] [", msg->total_len, msg->filename_len, 
            msg->filename, msg->text_len);
    print_hex(msg->text, msg->text_len);
    printf("] [");
    print_hex(msg->iv, block_len);
    printf("] [");
    print_hex(msg->salt, block_len);
    printf("] \n");

    hash = gcry_md_read(hd, SHA256);
    strcpy(ret_hash, (char*)hash);

    // TODO: Crash when called!!
    //gcry_md_close(hd);
    
    printf("\nhash : ");
    print_hex(ret_hash, digest_len);
    printf("\n");

    return ret_hash;
}

unsigned char* generate_outer_hash(const char *key, const size_t key_len,
                                    const char *msg, const size_t msg_len)
{
    unsigned char *hash, *ret_hash;
    gcry_error_t gcry_error;
    gcry_md_hd_t hd;
    unsigned int digest_len;

    printf("In outer hash\n");

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
    
    // Write the message
    gcry_md_write(hd, msg, msg_len);

    hash = gcry_md_read(hd, SHA256);
    strcpy(ret_hash, hash);

    gcry_md_close(hd);

    printf("\nhash : ");
    print_hex(ret_hash, digest_len);
    printf("\n");

    return ret_hash;
}
