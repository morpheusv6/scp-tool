#include "scp.h"

int serialize(const struct message *msg, const char *filepath);
int deserialize(const char *filepath, struct message *msg);
