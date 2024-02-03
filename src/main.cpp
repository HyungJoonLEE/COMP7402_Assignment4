#include "Brainpool.h"

int main(int argc, char *argv[]) {
    size_t alice_secret_len, bob_secret_len;

    auto *bob = new Brainpool("Bob");
    auto *alice = new Brainpool("Alice");

    // generate private, public key
    bob->generateKeys();
    alice->generateKeys();

    // shared secret key: exchange their public keys
    bob->exchangePublicKey(alice, bob_secret_len);
    alice->exchangePublicKey(bob, alice_secret_len);
    assertSharedSecretKey(alice, bob, alice_secret_len, bob_secret_len);

    // print each keys
    bob->printKeys();
    alice->printKeys();

    thread bob_thread(&Brainpool::bobThread, bob);
    thread alice_thread(&Brainpool::aliceThread, alice);
    bob_thread.join();
    alice_thread.join();


    freeKeys(alice);
    freeKeys(bob);

    delete(alice);
    delete(bob);
    return 0;
}