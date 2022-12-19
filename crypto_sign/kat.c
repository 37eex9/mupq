#include "api.h"
#include "hal.h"
#include "nistkatrng.h"
#include "randombytes.h"

#include <string.h>
#include <stdio.h>

#define NTESTS 100
#define NIST_SEED_LEN 48
#define MAXMLEN 2048

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_BYTES          NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_ALGNAME        NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_sign_keypair NAMESPACE(crypto_sign_keypair)
#define MUPQ_crypto_sign NAMESPACE(crypto_sign)
#define MUPQ_crypto_sign_open NAMESPACE(crypto_sign_open)
#define MUPQ_crypto_sign_signature NAMESPACE(crypto_sign_signature)
#define MUPQ_crypto_sign_verify NAMESPACE(crypto_sign_verify)


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
  // only meant for numbers with less than 10 digits
  char outs[prelen+10];

  for (int i = 1; i<=10; i++) {
    outs[prelen+i] = 0;
  }
  sprintf(outs, "%s%d", prefix, num);
  outs[prelen+10] = 0;
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
  unsigned char seed[NIST_SEED_LEN];
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];

  unsigned char mi[MAXMLEN];
  unsigned char sm[MAXMLEN+MUPQ_CRYPTO_BYTES];
  size_t smlen;
  size_t mlen;

  int r;
  size_t i, j, h, k;

  hal_setup(CLOCK_FAST);

  hal_send_str("==========================");


  for (k=0; k<NTESTS; k++) {

    randombytes_reset();

    // generate seed and message for round k
    for (h=0; h<=k; h++) {
      randombytes(seed, NIST_SEED_LEN);
      // message length
      i = 33*(h+1);
      randombytes(mi,i);
    }

    hal_send_str("");
    send_decimal("count = ", 8, k);
    send_hex("seed = ", 7, seed, NIST_SEED_LEN);
    nist_kat_init(seed, NULL, 256);
    send_decimal("mlen = ", 7, i);
    send_hex("msg = ", 6, mi, i);

    MUPQ_crypto_sign_keypair(pk, sk);

    send_hex("pk = ", 5, pk,MUPQ_CRYPTO_PUBLICKEYBYTES);
    send_hex("sk = ", 5, sk,MUPQ_CRYPTO_SECRETKEYBYTES);

    MUPQ_crypto_sign(sm, &smlen, mi, i, sk);

    send_decimal("smlen = ", 8, smlen);
    send_hex("sm = ", 5, sm, smlen);

    // By relying on m == sm we prevent having to allocate CRYPTO_BYTES twice
    r = MUPQ_crypto_sign_open(sm, &mlen, sm, smlen, pk);

    if(r)
    {
      hal_send_str("ERROR: signature verification failed");
      hal_send_str("#");
      return -1;
    }
    for(j=0;j<i;j++)
    {
      if(sm[j]!=mi[j])
      {
        hal_send_str("ERROR: message recovery failed");
        hal_send_str("#");
        return -1;
      }
    }
  }

  hal_send_str("#");
  return 0;
}