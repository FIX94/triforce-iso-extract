/*
 * This file can be used to work with the DES GnuPG
 * implementation without having any other includes
 */

#ifndef _DES_H_
#define _DES_H_

typedef struct _des_ctx
  {
    unsigned int encrypt_subkeys[32];
    unsigned int decrypt_subkeys[32];
  }
des_ctx[1];

int des_setkey (struct _des_ctx *, const unsigned char *);
int des_ecb_crypt (struct _des_ctx *, const unsigned char *, unsigned char *, int);
int is_weak_key ( const unsigned char *key );

#define des_ecb_encrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 0)
#define des_ecb_decrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 1)

#endif
