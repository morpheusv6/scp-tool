#include "scp.h"
#include <assert.h>
#include <regex.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

int get_ipaddress_port(const char* arg, char *ip, char *port);
char* get_filename(const char *filepath);
char* get_filename_without_ext(const char *filename);
void send_message(const struct message *msg, const char *filename, 
            const char *ip, const char *port);

int main(int argc, char* argv[])
{
    char *iv;
    gcry_cipher_hd_t hd;
    size_t buf_len;
    char *buffer;
    char *filepath;
    char passphrase[MAX_BUF_LEN];
    struct message msg;
    int i;
    char *ip, *port;
    char *filename, *enc_filename;
    FILE *fp;
    unsigned int digest_len;

    // TODO: Can be stored in msg
    size_t block_len;

    ip = NULL;
    port = NULL;
    
    if(argc < 2)
    {
        printf("Incorrect usage. ncsuenc <input file> [<output IP-addr:port>]\n");
        return 1;
    }

    msg.text = "";
    msg.iv = "";    
    initialize(&hd);
    
    if(argc >= 2)
    {
        filepath = (char*)calloc(1, sizeof(argv[1]));
        strcpy(filepath, argv[1]);
    }

    if(argc >= 3)
    {
        ip = (char*)calloc(1, sizeof(char) * strlen(argv[2]));
        port = (char*)calloc(1, sizeof(char) * strlen(argv[2]));

        get_ipaddress_port(argv[2], ip, port);
    }

    buf_len = read_file(filepath, &buffer);

    printf("\n\nEnter passphrase : ");
    gets(passphrase);

    filename = get_filename(filepath);
    msg.filename = (char*)calloc(1, strlen(filename) + 1);
    strcpy(msg.filename, filename);
    msg.filename_len = strlen(msg.filename) + 1;

    encrypt(hd, buffer, passphrase, &msg);    
    digest_len = gcry_md_get_algo_dlen(SHA256);
    
    printf("\nEncrypted :\n");
    print_hex(msg.text, msg.text_len);
    printf("\n");
    printf("HMAC : ");
    print_hex(msg.hmac, digest_len);
    printf("\n");

    msg.total_len = sizeof(msg.total_len) + sizeof(msg.filename_len) + 
                    msg.filename_len + msg.text_len + sizeof(msg.text_len) +
                    block_len + block_len;
    
    if(ip == NULL && port == NULL)
    {
        // Encrypted file(message) to be stored locally
        enc_filename = strcat( get_filename_without_ext(filename), ".ncsu");
        block_len = gcry_cipher_get_algo_keylen(ALG);

        fp = fopen(enc_filename, "wb");    
        // TODO: !fp check
        fwrite(&msg.total_len, sizeof(msg.total_len), 1, fp);
        fwrite(&msg.filename_len, sizeof(msg.filename_len), 1, fp);
        fwrite(msg.filename, msg.filename_len, 1, fp);
        fwrite(&msg.text_len, sizeof(msg.text_len), 1, fp);
        fwrite(msg.text, msg.text_len, 1, fp);
        fwrite(msg.iv, block_len, 1, fp);
        fwrite(msg.salt, block_len, 1, fp);
        fwrite(msg.hmac, digest_len, 1, fp);

        // TODO: Write the appended checksum
        fclose(fp);
    }
    else
    {
        send_message(&msg, filename, ip, port);
    }
    
    gcry_cipher_close(hd);
    
    return 0;
}

void send_message(const struct message *msg, const char *filename, 
            const char *ip, const char *port)
{
    int sockfd, portno, n;
    struct sockaddr_in server_addr;
    struct hostent *server;
    int i, remaining_len, len;
    size_t block_len = gcry_cipher_get_algo_keylen(ALG);
    char buffer[MAX_BUF_LEN];
    FILE *fp;
    char *enc_filename;
    unsigned int digest_len = gcry_md_get_algo_dlen(SHA256);

    portno = atoi(port);
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        // TODO: Create error handling method
        printf("Unable to create socket\n");
        return;
    }

    if((server = gethostbyname(ip)) == NULL)
    {
        printf("Cannot resolve ip address\n");
        return;
    }

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
            (char *)&server_addr.sin_addr.s_addr,
            server->h_length);
    server_addr.sin_port = htons(portno);
    if (connect(sockfd, (struct sockaddr *)&server_addr, 
                sizeof(server_addr)) < 0) 
    {
        printf("Cannot connect\n");
        return;
    }

    // Encrypted file(message) to be stored locally
    block_len = gcry_cipher_get_algo_keylen(ALG);    

    // Serialize
    // TODO: In memory serialization?
    fp = fopen("temp", "wb");    
    // TODO: !fp check
    fwrite(&msg->total_len, sizeof(msg->total_len), 1, fp);
    fwrite(&msg->filename_len, sizeof(msg->filename_len), 1, fp);
    fwrite(msg->filename, msg->filename_len, 1, fp);
    fwrite(&msg->text_len, sizeof(msg->text_len), 1, fp);
    fwrite(msg->text, msg->text_len, 1, fp);
    fwrite(msg->iv, block_len, 1, fp);
    fwrite(msg->salt, block_len, 1, fp);
    fwrite(msg->hmac, digest_len, 1, fp);

    fclose(fp);

    // Transfer the file over the network
    fopen("temp", "rb");
    while((n = fread(buffer, 1, MAX_BUF_LEN, fp)) != 0)
    {
        write(sockfd, buffer, n);
    }

    fclose(fp);
    remove("temp");

    close(sockfd);
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
    int reti;
    size_t num_regex_groups;
    regmatch_t *groups;
    int i, j, k;    

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

