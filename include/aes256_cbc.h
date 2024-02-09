#ifndef COMP7402_ASSIGNMENT4_AES256_CBC_H
#define COMP7402_ASSIGNMENT4_AES256_CBC_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

using namespace std;

#define DECL_OPENSSL_PTR(tname, free_func) \
    struct openssl_##tname##_dtor {            \
        void operator()(tname* v) {        \
            free_func(v);              \
        }                              \
    };                                 \
    typedef unique_ptr<tname, openssl_##tname##_dtor> tname##_t


DECL_OPENSSL_PTR(EVP_CIPHER_CTX, ::EVP_CIPHER_CTX_free);



class aes256_cbc {
private:
    vector<uint8_t> m_iv;

public:
    explicit aes256_cbc(vector<uint8_t> iv)
            : m_iv(move(iv)) {
    }

    void encrypt(const vector<uint8_t>& key, const vector<uint8_t>& message, vector<uint8_t>& output) const;
    void decrypt(const vector<uint8_t>& key, const vector<uint8_t>& message, vector<uint8_t>& output) const;
};


struct error : public exception {
private:
    string m_msg;

public:
    error(const string& message) : m_msg(message) {}

    error(const char* msg) : m_msg(msg, msg + strlen(msg)) {}

    virtual const char* what() const noexcept override {
        return m_msg.c_str();
    }
};


struct openssl_error: public virtual error {
private:
    int m_code = -1;
    string m_msg;

public:
    openssl_error(int code, const string& message) : error(message), m_code(code) {
        stringstream ss;
        ss << "[" << m_code << "]: " << message;
        m_msg = ss.str();
    }

    openssl_error(int code, const char* msg) : error(msg), m_code(code) {
        stringstream ss;
        ss << "[" << m_code << "]: " << msg;
        m_msg = ss.str();
    }

    const char* what() const noexcept override {
        return m_msg.c_str();
    }
};


static void throw_if_error(int res = 1, const char* file = nullptr, uint64_t line = 0) {
    unsigned long errc = ERR_get_error();

    if (res <= 0 || errc != 0) {
        if (errc == 0) {
            return;
        }
        vector<string> errors;
        while (errc != 0) {
            vector<uint8_t> buf(256);
            ERR_error_string(errc, (char*) buf.data());
            errors.push_back(string(buf.begin(), buf.end()));
            errc = ERR_get_error();
        }

        stringstream ss;
        ss << "\n";
        for (auto&& err : errors) {
            if (file != nullptr) {
                ss << file << ":" << (line - 1) << " ";
            }
            ss << err << "\n";
        }
        const string err_all = ss.str();
        throw openssl_error(errc, err_all);
    }
}


static vector<uint8_t> str_to_bytes(const string& message) {
    vector<uint8_t> out(message.size());
    for(size_t n = 0; n < message.size(); n++) {
        out[n] = message[n];
    }
    return out;
}


static string bytes_to_str(const vector<uint8_t>& bytes) {
    return string(bytes.begin(), bytes.end());
}



#endif //COMP7402_ASSIGNMENT4_AES256_CBC_H
