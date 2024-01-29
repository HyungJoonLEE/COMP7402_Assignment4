#include "Brainpool.h"

int main(int argc, char *argv[]) {
    size_t alice_secret_len, bob_secret_len;

    auto *alice = new Brainpool;
    auto *bob = new Brainpool;

    alice->createKey();
    bob->createKey();
    assert(alice != nullptr && bob != nullptr);

    alice->setPublicKey();
    bob->setPublicKey();
    assert(alice->getPublicKey() != nullptr && bob->getPublicKey() != nullptr);

    alice->setSecret(alice->getKey(), bob->getPublicKey(), &alice_secret_len);
    bob->setSecret(bob->getKey(), alice->getPublicKey(), &bob_secret_len);
    assert(alice->getSecret() != NULL && bob->getSecret() != NULL
           && alice_secret_len == bob_secret_len);

    for (int i = 0; i < alice_secret_len; i++)
        assert(alice->getSecret()[i] == bob->getSecret()[i]);

    EC_KEY_free(alice->getKey());
    EC_KEY_free(bob->getKey());
    OPENSSL_free(alice->getSecret());
    OPENSSL_free(bob->getSecret());

    return 0;
}