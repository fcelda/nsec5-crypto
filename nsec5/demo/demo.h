#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define error(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

void print_sign_result(const uint8_t *sign, size_t len);
void print_verify_result(bool valid);

const char *demo_name(void);

int demo(const char *filename, const char *hash_name,
	 const uint8_t *data, size_t data_len);
