#include <stdio.h>
#include <gcrypt.h>
#include <regex.h>

void print_gcry_error(const char* message, const gcry_error_t* error);
char* get_str_cipher_mode(int mode);
void print_hex(const char *str, const size_t str_len);

int get_ipaddress_port(const char *arg, char *ip, char *port);
size_t read_file(const char *filepath, char **buffer);
char* get_filename(const char *filepath);

