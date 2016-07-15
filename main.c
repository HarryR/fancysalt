/*
* Similar to https://github.com/katmagic/Shallot
* Generates random TweetNaCL compatible public keys
* that begin with your chosen prefix, either raw,
* hex or base32.
*/

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include "tweetnacl.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <ctype.h>

static FILE *rand_fh = NULL;

typedef struct {
	const char *base32;
	const char *raw;
	const char *hex;
	unsigned prefix_len;
	unsigned found;
	time_t start;
} cfg_t;

typedef struct {
	time_t start;
	size_t duration;
	size_t counter;
	size_t limit;
} benchmark_t;

static const char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static void
base32_encode(char *dst, unsigned char *src, int src_len) { // base32-encode hash
  uint8_t byte = 0,   // dst location
          offset = 0; // bit offset
  for(; byte < src_len; offset += 5) {
    if(offset > 7) {
      offset -= 8;
      src++;
    }
    dst[byte++] = BASE32_ALPHABET[(htobe16(*(uint16_t*)src) >> (11-offset))
                                  & (uint16_t)0x001F];
  }
  dst[byte] = '\0';
}

static int
base32_eq(const char *b32_in, const unsigned char *src, int max_bytes) {

  uint8_t byte = 0,   // dst location
          offset = 0; // bit offset
  for(; byte < max_bytes; offset += 5) {
    if(offset > 7) {
      offset -= 8;
      src++;
    }
    char b32_byte = BASE32_ALPHABET[(htobe16(*(uint16_t*)src) >> (11-offset))
                                  & (uint16_t)0x001F];
    if( b32_byte != b32_in[byte++] )
	return 0;
  }
  return 1;
}

void
randombytes(unsigned char * ptr, unsigned int length) 
{
	if( (rand_fh != NULL || (rand_fh = fopen("/dev/urandom", "rb")) != NULL)
	 && fread(ptr, length, 1, rand_fh) > 0 )
		return;

	fprintf(stderr, "Generating random data failed.");
	exit(1);
}

static void
print_hex( const char *what, size_t len )
{
	for( size_t N = 0; N < len; N++ )
		printf("%02X", (unsigned char)what[N]);
}

static inline int
is_good (cfg_t *cfg, unsigned char *data)
{
	const char * hex = "0123456789ABCDEF";

	if( cfg->raw ) {
		return memcmp(data, cfg->raw, cfg->prefix_len) == 0;
	} 
	if( cfg->hex ) {
		int I, O = 0, N = cfg->prefix_len;
		for( I = 0; I < N; I += 2, O++ ) {
			const char raw = data[O];
			const char what[2] = {
				hex[ (raw >> 4) & 0xF ],
				hex[ raw & 0xF ]
			};
			switch( I % 2 ) {
			case 0:
				if( what[0] != cfg->hex[I] )
					return 0;
			case 1:
				if( (I+1) < N && what[1] != cfg->hex[I + 1] )
					return 0;
			}
		}
		return 1;
	}
	if( cfg->base32 )
		return base32_eq(cfg->base32, data, cfg->prefix_len) ;
	
	return 0;
}

static inline uint64_t
xorshift128plus(uint64_t *s) {
	uint64_t x = s[0];
	uint64_t const y = s[1];
	s[0] = y;
	x ^= x << 23; // a
	s[1] = x ^ y ^ (x >> 17) ^ (y >> 26); // b, c
	return s[1] + y;
}

static void
benchmark_start (benchmark_t *bench, const char *name)
{
	printf("%s:\n", name);
	memset(bench, 0, sizeof(*bench));
	bench->start = time(NULL);
	bench->limit = 100;
}

static void
benchmark_end (benchmark_t *bench)
{
	printf("\n");
}

static void
benchmark_tick (benchmark_t *bench)
{
	if( bench->counter++ == bench->limit )
	{
		time_t now = time(NULL);
		int duration = now - bench->start;
		if( duration < 2 ) {
			bench->limit *= 1.5;
			return;
		}
		printf("%ld/s\n", bench->counter / duration);
		bench->counter = 0;
		bench->start = now;
		bench->duration += duration;
	} 
}

static void
benchmark_xorshift (benchmark_t *bench) {
     unsigned char pk[crypto_sign_PUBLICKEYBYTES];
     unsigned char sk[crypto_hash_BYTES];
     crypto_sign_keypair( pk, sk );
     benchmark_start(bench, "xorshift128plus");
     while( bench->duration < 20 ) {
	benchmark_tick(bench);
	xorshift128plus((uint64_t*)&sk);
     }
     benchmark_end(bench);
}

static void
benchmark_keypair_base(benchmark_t *bench) {
     unsigned char pk[crypto_sign_PUBLICKEYBYTES];
     unsigned char sk[crypto_hash_BYTES];
     crypto_sign_keypair( pk, sk );
     benchmark_start(bench, "crypto_sign_keypair_base");
     while( bench->duration < 20 ) {
	benchmark_tick(bench);
	crypto_sign_keypair_base(pk, sk);
     }
     benchmark_end(bench);
}

static void
benchmark_keypair (benchmark_t *bench) {
     unsigned char pk[crypto_sign_PUBLICKEYBYTES];
     unsigned char sk[crypto_hash_BYTES];
     benchmark_start(bench, "crypto_sign_keypair");
     while( bench->duration < 20 ) {
	benchmark_tick(bench);
        crypto_sign_keypair( pk, sk );
     }
     benchmark_end(bench);
}

static void
benchmark_hash (benchmark_t *bench) {
     unsigned char sk[crypto_hash_BYTES];
     benchmark_start(bench, "crypto_hash");
     while( bench->duration < 20 ) {
	benchmark_tick(bench);
	crypto_hash(sk, sk, crypto_hash_BYTES);
     }
     benchmark_end(bench);
}

static void
benchmark () {
	benchmark_t bench;
	benchmark_xorshift(&bench);
	benchmark_keypair(&bench);
	benchmark_keypair_base(&bench);
	benchmark_hash(&bench);
}

static void
worker_thread( cfg_t *cfg ) {
     unsigned char pk[crypto_sign_PUBLICKEYBYTES];
     unsigned char sk[crypto_hash_BYTES];
     cfg->start = time(NULL);
     int N = 0;
     crypto_sign_keypair( pk, sk );


     while( 1 ) {
	     //if( N++ == 10 ) {
		crypto_hash(sk, sk, crypto_hash_BYTES);
		//N = 0;
  	     //}
	     //xorshift128plus((uint64_t*)&sk);
	     crypto_sign_keypair_base(pk, sk);
	     if( is_good(cfg, pk) ) {
		cfg->found += 1;

		printf("PK: ");
		if( cfg->hex || cfg->raw ) {
			print_hex(pk, crypto_sign_PUBLICKEYBYTES);
			printf("\n");
			printf("SK: ");
			print_hex(sk, crypto_sign_SECRETKEYBYTES);
		}
		else if( cfg->base32 ) {
			char buf[crypto_sign_SECRETKEYBYTES*2];
			base32_encode(buf, pk, crypto_sign_PUBLICKEYBYTES);
			printf("%s\n", buf);
			printf("\n");
			printf("SK: ");
			base32_encode(buf, sk, crypto_sign_SECRETKEYBYTES);
			printf("%s\n", buf);
		} 
		printf("\n");
		printf("\n");
		fflush(stdout);
	     } 
     }
}

static void
print_usage ( char *arg ) {
	fprintf(stderr, "Usage: %s <opts>\n", basename(arg));
	fprintf(stderr, " -X <hex>\n");
	fprintf(stderr, " -R <raw-ascii>\n");
	fprintf(stderr, " -B <base32>\n");
	fprintf(stderr, " -b - Benchmark\n");
}

int
main( int argc, char **argv )
{
	cfg_t cfg;
	int flags, opt;

	memset(&cfg, 0, sizeof(cfg));

	while ((opt = getopt(argc, argv, "bX:R:B:")) != -1) {
		switch(opt) {
		case 'b':
			benchmark();
			exit(EXIT_SUCCESS);
		case 'X':
			cfg.hex = optarg;
			cfg.prefix_len = strlen(optarg);
			break;
		case 'R':
			cfg.raw = optarg;
			cfg.prefix_len = strlen(optarg);
			break;
		case 'B':
			cfg.base32 = optarg;
			cfg.prefix_len = strlen(optarg);
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if( cfg.hex == NULL && cfg.base32 == NULL && cfg.raw == NULL )
	{
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	} 
	worker_thread(&cfg);
}
