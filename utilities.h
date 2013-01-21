#include <stdio.h>
#include <gcrypt.h>

void print_gcry_error(const char* message, const gcry_error_t* error);
char* get_str_cipher_mode(int mode);
void print_hex(const char *str, const size_t str_len);
