#include "scp.h"

/*
 * Serializes the contents of the message into a file at the specified filepath
 * Parameters:
 *  msg[input]:         Message to serialize
 *  filepath[input]:    Path of the file to serialize to
 * Return value:    0 is successful, 1 otherwise
 */
int serialize(const struct message *msg, const char *filepath);

/*
 * Desrializes the contents of the file into the message
 * Parameters:
 *  filepath[input]:    Path of the file to deserialize
 *  msg[output]:        Deserialized message
 * Return value:    0 is successful, 1 otherwise
 */
int deserialize(const char *filepath, struct message *msg);
