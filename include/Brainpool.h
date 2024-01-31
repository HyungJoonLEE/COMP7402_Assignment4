#ifndef COMP7402_ASSIGNMENT4_BRAINPOOL_H
#define COMP7402_ASSIGNMENT4_BRAINPOOL_H

#include <cassert>
#include <cstdio>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

class Brainpool {
private:
    EC_KEY *private_key;
    const EC_POINT *public_key;
    unsigned char *shared_secret_key;
    string _name;
    void setPrivateKey();
    void setPublicKey();
    void setSecret(EC_KEY *key, const EC_POINT *peer_pub_key, size_t *secret_len);
public:
    Brainpool(string name);
    void generateKeys();
    void exchangePublicKey(Brainpool *bp, size_t &len);
    EC_KEY* getPrivateKey();
    const EC_POINT* getPublicKey();
    unsigned char* getSecret();
    void printKeys();
};

void assertSharedSecretKey(Brainpool *bp1, Brainpool *bp2, size_t &bp1_len, size_t &bp2_len);
void freeKeys(Brainpool *bp);

#endif //COMP7402_ASSIGNMENT4_BRAINPOOL_H
