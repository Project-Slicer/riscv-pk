// See LICENSE for license details.

#ifndef _UNCOMPRESS_H
#define _UNCOMPRESS_H

#include <stdint.h>

typedef void (*uncompress_callback_t)(uint8_t byte);

// Uncompresses the given file.
int uncompress(int kfd, uncompress_callback_t write_byte);

#endif
