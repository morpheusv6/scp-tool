#include "utilities.h"

void print_hex(const char *str, const size_t str_len)
{
    int i;
    for(i = 0; i < str_len; i++)
    {
        printf("%02X", (unsigned char)str[i]);
    }
}

size_t read_file(const char *filepath, char **buffer)
{
    FILE *fp;
    size_t file_size;
    
    // Read from the file
    if((fp = fopen(filepath, "rb")) == NULL)
    {
        printf("Cannot open file\n");
        return 0;
    }

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    if((*buffer = (char*)calloc(1, sizeof(char) * (file_size))) == NULL)
    {
        printf("Memory allocation failed\n");
        fclose(fp);
        return 0;
    }

    if(fread(*buffer, file_size, 1, fp) != 1)
    {
        printf("Unable to read from the file\n");
        free(*buffer);
        fclose(fp);
	    return 0;
    }

    fclose(fp);

    return file_size;
}

char* get_filename(const char *filepath)
{
    size_t  len;
    char *last_loc, *filename;
 
    if((last_loc = strrchr(filepath, '/')) == NULL)
    {
        filename = (char*)calloc(1, strlen(filepath) + 1);
        strcpy(filename, filepath);
        return filename;   
    }
        
    last_loc++; 
     
    len = strlen(last_loc);
    filename = (char*)calloc(1, len + 1);
    strncpy(filename, last_loc, len + 1);  // Copy including zero. 
    return filename;
}   

char* get_filename_without_ext(const char *filename)
{
    char *last_loc, *filename_without_ext;
    int i;

    if((last_loc = strrchr(filename, '.')) == NULL)
    {
        filename_without_ext = 
                (char*)calloc(1, sizeof(char) * strlen(filename) + 1);
        strcpy(filename_without_ext, filename);
        return filename_without_ext;   
    }
    
    filename_without_ext = 
                (char*)calloc(1, sizeof(char) * (last_loc - filename) + 1);
    for(i = 0; (filename + i) != last_loc; i++)
    {
        filename_without_ext[i] = filename[i];
    }

    filename_without_ext[i] = '\0';
    return filename_without_ext;
}

int get_ipaddress_port(const char *arg, char *ip, char *port)
{
    regex_t regex;
    size_t num_regex_groups;
    regmatch_t *groups;

    if(!regcomp(&regex, "(.*):(.*)", REG_EXTENDED|REG_ICASE))
    {
        num_regex_groups = regex.re_nsub + 1;
        groups = 
            (regmatch_t*)malloc(sizeof(regmatch_t) * num_regex_groups + 1);

        // TODO: 3 is a magic number
        if(!regexec(&regex, arg, num_regex_groups, groups, 0) &&
            num_regex_groups == 3)
        {
            memcpy(ip, &arg[groups[1].rm_so], 
                        groups[1].rm_eo - groups[1].rm_so);
            memcpy(port, &arg[groups[2].rm_so], 
                        groups[2].rm_eo - groups[2].rm_so);

            regfree(&regex);
            return 0;
        }
    }

    regfree(&regex);
    return 1;
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
