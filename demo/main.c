#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demo.h"

static void print_hex(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		printf("%02x%c", data[i], i % 16 == 15 ? '\n' : ' ');
	}

	if (len % 16 != 0) {
		printf("\n");
	}
}

void print_sign_result(const uint8_t *sign, size_t len)
{
	printf("# signature\n");
	print_hex(sign, len);
}

void print_verify_result(bool valid)
{
	printf("# verification\n%s\n", valid ? "succeeded" : "failed");
}

static void usage(const char *prog_name)
{
	printf("usage: %s <hash> <keyfile> <input-string>\n", prog_name);
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		usage(argv[0]);
		return 1;
	}

	const char *hash_name = argv[1];
	const char *keyfile   = argv[2];

	const uint8_t *data = (uint8_t *)argv[3];
	const size_t data_len = strlen(argv[3]);

	printf("## %s\n", demo_name());

	printf("# input\n");
	print_hex(data, data_len);

	return demo(keyfile, hash_name, data, data_len);
}
