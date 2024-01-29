#ifndef COMP7402_ASSIGNMENT4_BRAINPOOL_H
#define COMP7402_ASSIGNMENT4_BRAINPOOL_H

#include <cassert>
#include <cstdio>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <iostream>

using namespace std;

class Brainpool {
private:
    EC_KEY *key;
    const EC_POINT *public_key;
    unsigned char *secret;
public:

    void createKey();
    void setPublicKey();
    void setSecret(EC_KEY *key, const EC_POINT *peer_pub_key,
                              size_t *secret_len);
    EC_KEY* getKey();
    const EC_POINT* getPublicKey();
    unsigned char* getSecret();
};

#endif //COMP7402_ASSIGNMENT4_BRAINPOOL_H
