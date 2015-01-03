#pragma once

#include <stdint.h>
#include <stdlib.h>

#define error(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

void print_hex(const uint8_t *data, size_t len);

const char *demo_name(void);

int demo(const char *filename, const char *hash_name,
	 const uint8_t *data, size_t data_len);
