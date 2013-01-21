#include "utilities.h"

void print_hex(const char *str, const size_t str_len)
{
    int i;
    for(i = 0; i < str_len; i++)
    {
        printf("%02X", (unsigned char)str[i]);
    }
}

char* get_str_cipher_mode(int mode)
{
    switch(mode)
    {
        case GCRY_CIPHER_MODE_NONE:
            return "NONE";
        
        case GCRY_CIPHER_MODE_ECB:
            return "ECB";
        
        case GCRY_CIPHER_MODE_CFB:
            return "CFB";
        
        case GCRY_CIPHER_MODE_CBC:
            return "CBC";
        
        case GCRY_CIPHER_MODE_STREAM:
            return "Stream";
        
        case GCRY_CIPHER_MODE_OFB:
            return "OFB";
        
        case GCRY_CIPHER_MODE_CTR:
            return "Counter";
        
        case GCRY_CIPHER_MODE_AESWRAP:
            return "AES wrap";
        
        default:
            return "unknown";
    }
}

void print_gcry_error(const char* message, const gcry_error_t* error)
{
    printf("%s: [%d] %s - %s\n", 
            message, 
            gcry_err_code(*error),
            gcry_strerror(*error),
            gcry_strsource(*error));
}
