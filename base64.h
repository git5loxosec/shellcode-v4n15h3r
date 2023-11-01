#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

size_t base64_encode(const void *data, size_t input_length, char *encoded_data, size_t output_length);

size_t base64_decode(const char *encoded_data, size_t input_length, void *data, size_t output_length);

#endif
