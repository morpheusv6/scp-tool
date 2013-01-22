#include "scp.h"
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

void send_message(const struct message *msg, const char *filename, 
            const char *ip, const char *port);

int main(int argc, char* argv[])
{
    gcry_cipher_hd_t hd;
    size_t buf_len, block_len;
    char *buffer, *filepath, *filename, *enc_filename;
    char passphrase[MAX_BUF_LEN];
    struct message msg;
    char *ip, *port;
    FILE *fp;
    unsigned int digest_len;

    ip = port = NULL;

    if(argc < 2)
    {
        printf("Incorrect usage. "
                "ncsuenc <input file> [<output IP-addr:port>]\n");
        return 1;
    }

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

    printf("\nEnter passphrase : ");
    gets(passphrase);

    filename = get_filename(filepath);
    msg.filename = (char*)calloc(1, strlen(filename) + 1);
    strcpy(msg.filename, filename);
    msg.filename_len = strlen(msg.filename) + 1;
    msg.text_len = buf_len;

    encrypt(hd, buffer, passphrase, &msg); 
    digest_len = gcry_md_get_algo_dlen(SHA256);

    /*printf("\nEncrypted :\n");
    print_hex(msg.text, msg.text_len);
    printf("\n");
    printf("HMAC : ");
    print_hex(msg.hmac, digest_len);
    printf("\n");*/

    block_len = gcry_cipher_get_algo_keylen(ALG);    
    msg.total_len = sizeof(msg.total_len) + sizeof(msg.filename_len) + 
                    msg.filename_len + msg.text_len + sizeof(msg.text_len) +
                    block_len + block_len;

    if(ip == NULL && port == NULL)
    {
        // Encrypted file(message) to be stored locally
        enc_filename = strcat( get_filename_without_ext(filename), ".ncsu");
        serialize(&msg, enc_filename);
    }
    else
    {
        send_message(&msg, filename, ip, port);
        free(ip);
        free(port);
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
    char buffer[MAX_BUF_LEN];
    FILE *fp;
    const char *temp = "temp";
    
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

    // Serialize
    serialize(msg, "temp");

    // Transfer the file over the network
    fp = fopen("temp", "rb");
    while((n = fread(buffer, 1, MAX_BUF_LEN, fp)) != 0)
    {
        write(sockfd, buffer, n);
    }

    fclose(fp);
    remove("temp");

    close(sockfd);
}
