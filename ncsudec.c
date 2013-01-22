#include "scp.h"

#include <sys/socket.h>
#include <netinet/in.h>

char* recv_file(const char *port);
void write_text_to_file(const struct message *msg);

int main(int argc, char* argv[])
{
    gcry_cipher_hd_t hd;
    char *filepath, *port;
    char passphrase[MAX_BUF_LEN];
    struct message msg;
    FILE *fp;
    size_t block_len;
    unsigned int digest_len;    
   
    if(argc < 3)
    {
        printf("Incorrect usage. "
                "ncsudec ncsudec [-d <port>] [-i <input file>]\n");
        return 1;
    }

    initialize(&hd);
    
    if(argc >= 3)
    {
        if(strcmp(argv[1], "-d") == 0)
        {
            port = (char*)calloc(1, strlen(argv[2]) + 1);
            strcpy(port, argv[2]);
            filepath = recv_file(port);
            free(port);
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

        deserialize(filepath, &msg);

        // Remove the temporary file
        if(strcmp(argv[1], "-d") == 0)
        {
            remove(filepath);
        }

        printf("\n\nEnter passphrase : ");
        gets(passphrase);

        decrypt(hd, msg.text, passphrase, &msg);

        write_text_to_file(&msg);

        //printf("\nDecrypted [%s] : %s\n", msg.filename, msg.text);
        gcry_cipher_close(hd);
     }
   
    return 0;
}

void write_text_to_file(const struct message *msg)
{
    char buffer[MAX_BUF_LEN];
    FILE *fp;
    int i, n;
    
    fp = fopen(msg->filename, "wb");

    //for(i = 0; i < msg->text_len; i++)
    {
        fwrite(msg->text, msg->text_len - 1, 1, fp);
    }

    fclose(fp);
}

char* recv_file(const char *port)
{
    int sockfd, portno, n, newsockfd;
    struct sockaddr_in server_addr, cli_addr;
    socklen_t clilen;
    char *filename;

    char buffer[MAX_BUF_LEN]; 
    FILE *fp = NULL;

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
