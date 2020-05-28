#include "getrandom.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <time.h>


#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#define DEV_URANDOM "/dev/urandom"
#endif /* !_WIN32 */

/* BASE62_DIGIT(x) returns the ascii code of the digit x in base 62
 * (0 <= x < 62).
 * Example: BASE62_DIGIT(12) => 'C' */
#define BASE62_DIGIT(x) (\
	((x) < 10U) \
		? ('0' + (x)) \
		: ((x) < 36U) \
			? ('A' + (x) - 10) \
			: ((x) < 62U) \
				? ('a' + (x) - 36) \
				: '?')
/* HEX_DIGIT(x) returns the ascii code of the digit x in hexadecimal
 * (0 <= x < 16).
 * Example: HEX_DIGIT(12) => 'C' */
#define HEX_DIGIT(x) (((x) < 16U) ? BASE62_DIGIT(x) : '?')


static char *str;
static char *buf;

// #define rand() myrand()
// #define srand(s)

int myrand(void) {
	static int r = 0;
	return r++;
}

char *getrandom_str(size_t size)
{
	static bool srand_called = false;
#ifdef _WIN32
	unsigned short chunk;
	const size_t chunksize = sizeof chunk;
#endif
	const size_t strsize = size * 2 + 3;
	size_t written = 0;
	const char *bufit;
	char *strit;

	assert(size > 0);

	if (!srand_called) {
		srand((unsigned) time(NULL));
		srand_called = true;
	}

	str = malloc(strsize);
	if (!str) {
		perror("malloc");
		abort();
	}

	buf = malloc(size);
	if (!buf) {
		free(str);
		perror("malloc");
		abort();
	}

#ifdef _WIN32
	while (written + chunksize < size) {
		chunk = rand();
		memcpy(buf + written, &chunk, chunksize);
		written += chunksize;
	}
	if (written < size) {
		chunk = rand();
		memcpy(buf + written, &chunk, size - written);
	}
#else /* !_WIN32 */
	{
		const int flags = O_RDONLY

#ifdef O_NOCTTY
			| O_NOCTTY
#endif
#ifdef O_NOFOLLOW
			| O_NOFOLLOW
#endif
		;
		ssize_t bytes_read;

		const int fd = open(DEV_URANDOM, flags);
		if (fd == -1) {
			perror("Failed to open " DEV_URANDOM);
			free(str);
			free(buf);
			abort();
		}
		bytes_read = read(fd, buf, size);
		if (bytes_read == -1) {
			perror("Failed to read from " DEV_URANDOM);
			free(str);
			free(buf);
			if (close(fd) == -1)
				perror("Failed to close " DEV_URANDOM);
			abort();
		}
		if (close(fd) == -1) {
			perror("Failed to close " DEV_URANDOM);
			free(str);
			free(buf);
			abort();
		}
		assert((size_t) bytes_read == size);
	}
#endif


	strncpy(str, "0x", 2);
	strit = str + 2;
	bufit = buf;
	for (written = 0; written < size; ++written) {
		const unsigned char c = *bufit++;
		*strit++ = HEX_DIGIT((c & 0x00f0) >> 4);
		*strit++ = HEX_DIGIT(c & 0x000f);
	}
	*strit = '\0';

	free(buf);

	return str;
}

char *test_str;
void test_getrandom(unsigned ntests)
{
	test_str = getrandom_str(64);
	puts(test_str);
	free(test_str);
	if (ntests - 1)
		test_getrandom(ntests - 1);
}
