#include "scp.h"

int serialize(const struct message *msg, const char *filepath)
{
    size_t block_len;
    unsigned int digest_len;
    char *buffer;
    FILE *fp;
                                                                                    
    // Serialize                                                                
    // TODO: In memory serialization?                                           
    if(!(fp = fopen(filepath, "wb")))
    {
        printf("Cannot serialize\n");
        return 1;
    }

    digest_len = gcry_md_get_algo_dlen(SHA256);
    block_len = gcry_cipher_get_algo_keylen(ALG);                               
    
    fwrite(&msg->total_len, sizeof(msg->total_len), 1, fp);                     
    fwrite(&msg->filename_len, sizeof(msg->filename_len), 1, fp);               
    fwrite(msg->filename, msg->filename_len, 1, fp);                            
    fwrite(&msg->text_len, sizeof(msg->text_len), 1, fp);                       
    fwrite(msg->text, msg->text_len, 1, fp);                                    
    fwrite(msg->iv, block_len, 1, fp);                                          
    fwrite(msg->salt, block_len, 1, fp);                                        
    fwrite(msg->hmac, digest_len, 1, fp);                                       
    fclose(fp);                                        

    return 0;
}

int deserialize(const char *filepath, struct message *msg)
{
    size_t block_len;
    unsigned int digest_len;
    FILE *fp;
   
    // Read the file contents                                               
    if(!(fp = fopen(filepath, "rb")))
    {
        printf("Unable to deserialize\n");
        return 1;
    }

    block_len = gcry_cipher_get_algo_keylen(ALG);                           
    digest_len = gcry_md_get_algo_dlen(SHA256);                             
    
    fread(&msg->total_len, sizeof(msg->total_len), 1, fp);                    
    fread(&msg->filename_len, sizeof(msg->filename_len), 1, fp);              
    
    msg->filename = (char*)calloc(1, msg->filename_len);                      
    
    fread(msg->filename, msg->filename_len, 1, fp);                           
    fread(&msg->text_len, sizeof(msg->text_len), 1, fp);                      
    
    msg->text = (char*)calloc(1, msg->text_len);                              
    msg->iv = (char*)calloc(1, block_len);                                   
    msg->salt =  (char*)calloc(1, block_len);                                
    msg->hmac = (unsigned char*)calloc(1, digest_len);                       
    
    fread(msg->text, msg->text_len, 1, fp);                                   
    fread(msg->iv, block_len, 1, fp);                                        
    fread(msg->salt, block_len, 1, fp);                                      
    fread(msg->hmac, digest_len, 1, fp);                                     

    fclose(fp);                                  

    return 0;
}
