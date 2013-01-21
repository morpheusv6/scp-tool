#include "scp.h"
#include <assert.h>
#include <regex.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

int get_ipaddress_port(const char* arg, char *ip, char *port);

char* recv_file(const char *port);
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
    FILE *fp;
    size_t block_len;
    unsigned int digest_len = gcry_md_get_algo_dlen(SHA256);        
    if(argc < 2)
    {
        printf("Incorrect usage. ncsuenc <input file> [<output IP-addr:port>]\n");
        return 1;
    }

    msg.text = "";
    msg.iv = "";    
    initialize(&hd);
    
    if(argc >= 3)
    {
        if(strcmp(argv[1], "-d") == 0)
        {
            port = (char*)calloc(1, strlen(argv[2]) + 1);
            strcpy(port, argv[2]);
            filepath = recv_file(port);
        }
        else if(strcmp(argv[1], "-i") == 0)
        {
            filepath = (char*)calloc(1, strlen(argv[2]) + 1);
            strcpy(filepath, argv[2]); 
        }

        if(filepath == NULL)
        {
            return 1;
        }

        block_len = gcry_cipher_get_algo_keylen(ALG);

        // Read the file contents
        fp = fopen(filepath, "rb");
        
        fread(&msg.total_len, sizeof(msg.total_len), 1, fp);
        fread(&msg.filename_len, sizeof(msg.filename_len), 1, fp);
        
        msg.filename = (char*)calloc(1, msg.filename_len);
        fread(msg.filename, msg.filename_len, 1, fp);

        fread(&msg.text_len, sizeof(msg.text_len), 1, fp);
        msg.text = (char*)calloc(1, msg.text_len);
        msg.iv = (char*)calloc(1, block_len);
        msg.salt =  (char*)calloc(1, block_len);
        msg.hmac = (unsigned char*)calloc(1, digest_len);
        
        fread(msg.text, msg.text_len, 1, fp);
        fread(msg.iv, block_len, 1, fp);
        fread(msg.salt, block_len, 1, fp);
        fread(msg.hmac, digest_len, 1, fp);
        
        fclose(fp);

        // Remove the temporary file
        if(strcmp(argv[1], "-d") == 0)
        {
            remove(filepath);
        }

        // TODO: Read and assign message checksum
    }

    printf("\n\nEnter passphrase : ");
    gets(passphrase);

    decrypt(hd, msg.text, passphrase, &msg);
    
    printf("\nDecrypted [%s] : %s\n", msg.filename, msg.text);
    gcry_cipher_close(hd);
    return 0;
}

char* recv_file(const char *port)
{
    int sockfd, portno, n, newsockfd;
    struct sockaddr_in server_addr, cli_addr;
    struct hostent *server;
    socklen_t clilen;
    int i;
    char *filename;
    struct message msg;
    int retval;
    int remaining_len, len;

    char buffer[MAX_BUF_LEN]; 
    FILE *fp = NULL;

    size_t block_len = gcry_cipher_get_algo_keylen(ALG);
    filename = NULL;
    
    portno = atoi(port);
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        // TODO: Create error handling method
        printf("Unable to create socket\n");
        return NULL;
    }

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&server_addr,
                  sizeof(server_addr)) < 0) 
    {
        printf("Unable to bind to port %s\n", port);
    }
                                     
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    
    printf("Waiting for incoming connection...\n");
    newsockfd = accept(sockfd, 
                (struct sockaddr *)&cli_addr, 
                    &clilen);

    // Read into a temporary file
    filename = "temp.ncsu";
    fp = fopen(filename, "wb");
    while((n = read(newsockfd, buffer, MAX_BUF_LEN)) > 0)
    {
        fwrite(buffer, 1, n, fp);
    }

    close(newsockfd);
    close(sockfd);

    fclose(fp);

    return filename;
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
