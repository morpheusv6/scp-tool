#include <stdio.h>
#include <gcrypt.h>
#include <regex.h>

/*
 * Prints the descriptive gcrypt error 
 * Parameters:
 *  message[input]: Informative message
 *  error[input]:   Encapsulates the gcrypt error
 */
void print_gcry_error(const char* message, const gcry_error_t* error);

/*
 * Returns the descriptive name of the specified cipher mode
 * Parameters:
 *  mode[input]:    Cipher mode
 * Return value:    Descriptive name of the cipher mode
 */
char* get_str_cipher_mode(int mode);

/*
 * Prints the string in hex format
 * Parameters:
 *  str[input]:     String to be printed in hex
 *  str_len[input]: Length of the string
 */
void print_hex(const char *str, const size_t str_len);

/*
 * Parse the IP_address:Port string (uses regex)
 * Parameters:
 *  arg[input]:     String to parse
 *  ip[output]:     IP address component of the string
 *  port[output]:   Port component of the string
 * Return value:    0 is successful, 1 otherwise
 */
int get_ipaddress_port(const char *arg, char *ip, char *port);

/*
 * Reads the file from the specified filepath
 * Parameters:
 *  filepath[input]:    Path of the file to be read
 *  buffer[output]:     Contents of the read file
 * Return value:    Positive number of bytes read from the file if successful, 
                    0 otherwise
 */
size_t read_file(const char *filepath, char **buffer);

/* 
 * Retrieves the file name from the filepath
 * Parameters:
 *  filepath[input]:    Absolute or relative path of the file
 * Return value:    The filename (including extension)
 */
char* get_filename(const char *filepath);

