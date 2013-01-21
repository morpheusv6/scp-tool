#include "scp.h"

unsigned char* generate_hash(const char *key, const size_t key_len,
                                const struct message *msg);
unsigned char* generate_inner_hash(const char *key, 
                                    const size_t key_len, 
                                    const struct message *msg);
unsigned char* generate_outer_hash(const char *key, 
                                    const size_t key_len,
                                    const char* msg, 
                                    const size_t msg_len);
