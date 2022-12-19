#include "api.h"
#include "hal.h"
#include "nistkatrng.h"
#include "randombytes.h"

#include <string.h>
#include <stdio.h>

#define NTESTS 100
#define NIST_SEED_LEN 48

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)


void send_hex(char *prefix, unsigned long long prelen, unsigned char *ptr, unsigned long long length)
{
  char outs[prelen+length*2+1];
  unsigned long long i;

  sprintf(outs, "%s", prefix);

  for(i=0;i<length;i++)
    sprintf(prelen+outs+2*i, "%02X", ptr[i]);
  outs[prelen+2*length] = 0;
  hal_send_str(outs);
}


void send_decimal(char *prefix, unsigned long long prelen, int num)
{
  // only meant for numbers with less than 3 digits
  char outs[prelen+3];

  outs[prelen+2] = 0;
  outs[prelen+3] = 0;
  sprintf(outs, "%s%d", prefix, num);
  outs[prelen+3] = 0;
  hal_send_str(outs);
}


void randombytes_reset(void)
{
  unsigned char entropy_input[NIST_SEED_LEN];

  for (int i=0; i<NIST_SEED_LEN; i++) {
    entropy_input[i] = i;
  }

  nist_kat_init(entropy_input, NULL, 256);
}


int main(void)
{
  unsigned char       seed[NIST_SEED_LEN];
  unsigned char       ct[MUPQ_CRYPTO_CIPHERTEXTBYTES], ss[MUPQ_CRYPTO_BYTES], ss1[MUPQ_CRYPTO_BYTES];
  unsigned char       pk[MUPQ_CRYPTO_PUBLICKEYBYTES], sk[MUPQ_CRYPTO_SECRETKEYBYTES];

  hal_setup(CLOCK_FAST);
  hal_send_str("\n==========================\n");
  for (int i=0; i<NTESTS; i++) {

    randombytes_reset();

    // generate seed for round i
    for (int j=0; j<=i; j++) {
        randombytes(seed, NIST_SEED_LEN);
    }

    hal_send_str("");
    send_decimal("count = ", 8, i);
    send_hex("seed = ", 7, seed, NIST_SEED_LEN);
    nist_kat_init(seed, NULL, 256);

    MUPQ_crypto_kem_keypair(pk, sk);
    send_hex("pk = ", 5, pk, MUPQ_CRYPTO_PUBLICKEYBYTES);
    send_hex("sk = ", 5, sk, MUPQ_CRYPTO_SECRETKEYBYTES);

    MUPQ_crypto_kem_enc(ct, ss, pk);
    send_hex("ct = ", 5, ct, MUPQ_CRYPTO_CIPHERTEXTBYTES);

    MUPQ_crypto_kem_dec(ss1, ct, sk);
    send_hex("ss = ", 5, ss1, MUPQ_CRYPTO_BYTES);
  }

  hal_send_str("#");
  return 0;
}
