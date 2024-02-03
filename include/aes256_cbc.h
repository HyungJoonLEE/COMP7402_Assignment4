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

struct error : public exception {
private:
    string m_msg;

public:
    error(const string& message)
            : m_msg(message) {
    }

    error(const char* msg)
            : m_msg(msg, msg + strlen(msg)) {
    }

    virtual const char* what() const noexcept override {
        return m_msg.c_str();
    }
};

struct openssl_error: public virtual error {
private:
    int m_code = -1;
    string m_msg;

public:
    openssl_error(int code, const string& message)
            : error(message),
              m_code(code) {
        stringstream ss;
        ss << "[" << m_code << "]: " << message;
        m_msg = ss.str();

    }

    openssl_error(int code, const char* msg)
            : error(msg),
              m_code(code) {
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

class aes256_cbc {
private:
    vector<uint8_t> m_iv;

public:
    explicit aes256_cbc(vector<uint8_t> iv)
            : m_iv(move(iv)) {
    }

    void encrypt(const vector<uint8_t>& key, const vector<uint8_t>& message, vector<uint8_t>& output) const {
        output.resize(message.size() * AES_BLOCK_SIZE);
        int inlen = message.size();
        int outlen = 0;
        size_t total_out = 0;

        EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
        throw_if_error(1, __FILE__, __LINE__);

        // todo: sha256 function
        // const vector<uint8_t> enc_key = key.size() != 32 ? sha256(key) : key;

        const vector<uint8_t> enc_key = key;

        int res;
        res = EVP_EncryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), m_iv.data());
        throw_if_error(res, __FILE__, __LINE__);
        res = EVP_EncryptUpdate(ctx.get(), output.data(), &outlen, message.data(), inlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;
        res = EVP_EncryptFinal(ctx.get(), output.data()+total_out, &outlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;

        output.resize(total_out);
    }

    void decrypt(const vector<uint8_t>& key, const vector<uint8_t>& message, vector<uint8_t>& output) const {
        output.resize(message.size() * 3);
        int outlen = 0;
        size_t total_out = 0;

        EVP_CIPHER_CTX_t ctx(EVP_CIPHER_CTX_new());
        throw_if_error();

        // todo: sha256 function const vector<uint8_t> enc_key = key.size() != 32 ? sha256(key.to_string()) : key;

        // means you have already 32 bytes keys
        const vector<uint8_t> enc_key = key;
        vector<uint8_t> target_message;
        vector<uint8_t> iv;

        iv = m_iv;
        target_message = message;

        int inlen = target_message.size();

        int res;
        res = EVP_DecryptInit(ctx.get(), EVP_aes_256_cbc(), enc_key.data(), iv.data());
        throw_if_error(res, __FILE__, __LINE__);
        res = EVP_DecryptUpdate(ctx.get(), output.data(), &outlen, target_message.data(), inlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;
        res = EVP_DecryptFinal(ctx.get(), output.data()+outlen, &outlen);
        throw_if_error(res, __FILE__, __LINE__);
        total_out += outlen;

        output.resize(total_out);
    }
};

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
