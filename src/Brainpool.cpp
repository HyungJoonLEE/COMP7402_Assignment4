#include "Brainpool.h"

mutex mtx;
condition_variable cv;
vector<uint8_t> enc_result;
vector<uint8_t> dec_result;
bool ready = false;
bool processed = false;
const string iv = "1234567890123456";
const aes256_cbc encryptor(str_to_bytes(iv));

Brainpool::Brainpool(string name) : _name(move(name)) {
    private_key = nullptr;
    public_key = nullptr;
    shared_secret_key = nullptr;
}


void Brainpool::generateKeys() {
    this->setPrivateKey();
    assert(this->getPrivateKey() != nullptr);

    this->setPublicKey();
    assert(this->getPublicKey() != nullptr);
}


void Brainpool::setPrivateKey() {
    if (NULL == (private_key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1))) {
        printf("Failed to create key curve\n");
        return;
    }

    // Creates a new ec private (and optional a new public) key.
    if (1 != EC_KEY_generate_key(private_key)) {
        printf("Failed to generate key\n");
        return;
    }
}


void Brainpool::setPublicKey() {
    public_key = EC_KEY_get0_public_key(private_key);
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
    const EC_POINT *pub = EC_KEY_get0_public_key(private_key);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {
        cout << "[ " << _name << " ]" << endl;
        cout << "X = ";
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        cout << "Y = ";
        BN_print_fp(stdout, y);
        putc('\n', stdout);
        cout << endl;
    }

    free(x);
    free(y);
}


void Brainpool::setSecret(EC_KEY *key, const EC_POINT *peer_pub_key,
                                     size_t *secret_len) {
    int field_size;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    *secret_len = (field_size + 7) / 8;

    if (nullptr == (shared_secret_key = (unsigned char *)OPENSSL_malloc(*secret_len))) {
        printf("Failed to allocate memory for secret");
        return;
    }

    *secret_len = ECDH_compute_key(shared_secret_key, *secret_len,
                                   peer_pub_key, key, NULL);

    if (*secret_len <= 0) {
        OPENSSL_free(shared_secret_key);
        return;
    }
}


EC_KEY* Brainpool::getPrivateKey() {
    return private_key;
}


const EC_POINT *Brainpool::getPublicKey() {
    return public_key;
}


unsigned char *Brainpool::getSecret() {
    return shared_secret_key;
}


void Brainpool::printKeys() {
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    cout << "[ " << _name << " ]" << endl;
    EC_KEY_print(bio, private_key, NULL);

    cout << "Shared Secret Key:" << endl;
    for (int i = 0; i < 32; i++) {
        cout << setfill('0') << setw(2) << hex << uppercase << (int) shared_secret_key[i] << " ";
    }
    cout << endl << endl;
    BIO_free(bio);
}


void Brainpool::exchangePublicKey(Brainpool *bp, size_t &len) {
    setSecret(this->getPrivateKey(), bp->getPublicKey(), &len);
    assert(this->getSecret() != nullptr);
}


void Brainpool::bobThread() {
    vector<uint8_t> key(this->getSecret(), this->getSecret() + 32);
    int count = 0;
    while(1) {
        unique_lock<mutex> lock(mtx);
        signal(SIGINT, reinterpret_cast<__sighandler_t>(my_handler));
        cout << "Ctrl + C twice to Exit the program\n" << endl;
        string plainText = getInput("Enter plain text: ");
        encryptor.encrypt(key, str_to_bytes(plainText), enc_result);

        cout << "Encrypted Text: " << bytes_to_str(enc_result) << endl;
        for (auto elem : enc_result) {
            cout << hex << setfill('0') << setw(2) << static_cast<int>(elem) << ' ';
            count++;
            if (count == 16) {
                cout << endl;
                count = 0;
            }
        }

        ready = true; // Set ready for Alice.
        cv.notify_one(); // Notify Alice's thread
        cv.wait(lock, [] { return processed; }); // Wait for Alice to process
        processed = false; // Reset processed for the next iteration
        dec_result.clear();
    }
}


void Brainpool::aliceThread() {
    vector<uint8_t> key(this->getSecret(), this->getSecret() + 32);

    while(1) {
        unique_lock<mutex> lock(mtx);
        cv.wait(lock, [] { return ready; }); // Wait for Bob to encrypt and notify.

        encryptor.decrypt(key, enc_result, dec_result);
        cout << ">> Original Text: " << bytes_to_str(dec_result) << endl << endl;

        ready = false;
        processed = true;
        cv.notify_one();
        enc_result.clear();
    }
}


string Brainpool::getInput(const string &prompt) {
    string input;
    do {
        cout << prompt;
        getline(cin, input);  // getline - read the whole line
        input[input.size()] = '\0';
    } while (input.empty());
    return input;
}


void freeKeys(Brainpool *bp) {
    EC_KEY_free(bp->getPrivateKey());
    OPENSSL_free(bp->getSecret());
}


void assertSharedSecretKey(Brainpool *bp1, Brainpool *bp2, size_t &bp1_len, size_t &bp2_len) {
    // shared secret key length check
    assert(bp1_len == bp2_len);

    // shared secret key is identical
    for (int i = 0; i < bp1_len; i++) {
        assert(bp1->getSecret()[i] == bp2->getSecret()[i]);
    }
}


void my_handler(sig_t s) {
    cout << "Caught signal " << s << " [ Exit the program ]" << endl;
    exit(1);
}
