// CryptoExtension.cpp : Defines the entry point for the application.
//

#include "../api/RSAExtension.h"

#include <iostream>

#include <rsa.h>
#include <integer.h>
#include <osrng.h>

using namespace CryptoPP;
using namespace std;

namespace RSAExtension {
    GMDLL char* DLLTest() {
        return (char*)"testing.";
    }

    // Generate the key components and outputs a set of macros to console that can be used within GMS2
    GMDLL char* DLLGenerateKeys() {
        ///////////////////////////////////////
        // Pseudo Random Number Generator
        AutoSeededRandomPool rng;

        ///////////////////////////////////////
        // Generate Parameters
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 3072);

        ///////////////////////////////////////
        // Generated Parameters
        const Integer& n = params.GetModulus();
        const Integer& p = params.GetPrime1();
        const Integer& q = params.GetPrime2();
        const Integer& d = params.GetPrivateExponent();
        const Integer& e = params.GetPublicExponent();

        ///////////////////////////////////////
        // Dump
        cout << "// RSA Parameters:" << endl;
        cout << "#macro RSA_N \"" << n << "\"" << endl;
        cout << "#macro RSA_P \"" << p << "\"" << endl;
        cout << "#macro RSA_Q \"" << q << "\"" << endl;
        cout << "#macro RSA_D \"" << d << "\"" << endl;
        cout << "#macro RSA_E \"" << e << "\"" << endl;
        cout << endl;

        return (char*)"wow!";
    }

    char* toCharArray(string input) {
        char* array = new char[input.length() + 1];
        input.copy(array, input.length() + 1);
        return array;
    }

    // GMS2 forces you to provide all args as the same data type when you have more than 4, for some reason.
    // So to cut down on arguments, we can pass all the key components as a single string, pipe delimited
    vector<char*> tokenify(char* input, char* delimiter) {
        vector<char*> v;

        char* chars = strtok(input, delimiter);
        while (chars) {
            v.push_back(chars);
            chars = strtok(NULL, delimiter);
        }

        return v;
    }

    char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F' };

    std::string charToHex(char const ch) {
        std::string str;
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
        return str;
    }

    std::string charsToHex(string bytes) {
        std::string str;
        for (int i = 0; i < bytes.length(); ++i) {
            const char ch = bytes.at(i);
            str.append(&hex[(ch & 0xF0) >> 4], 1);
            str.append(&hex[ch & 0xF], 1);
            str.append(" ");
        }
        return str;
    }

    vector<byte> convertToBytes(const int* buffer, double length) {
        vector<byte> bytes;

        /* 
            The buffer provided has the granularity of bytes, however we can only iterate it in ints.
            To account for this, the buffer is padded.
            The provided length is only for the actual bytes we care about, not including padding,
            so we need to increase it to a limit that makes sure we iterate through all the ints.
        */
        int byteCount = 0;
        int limit = length / 4;
        int mod = int(length) % 4;
        if (mod > 0) {
            limit = (length + (4 - mod)) / 4;
        }

        for (int i = 0; i < limit; i++) {
            unsigned char b[4];
            unsigned long n = buffer[i];
            b[3] = (n >> 24) & 0xFF;
            b[2] = (n >> 16) & 0xFF;
            b[1] = (n >> 8) & 0xFF;
            b[0] = n & 0xFF;

            for (int j = 0; j < 4; j++) {
                bytes.push_back(b[j]);

                if (++byteCount >= length) {
                    // We've reached the last byte before the padding, so we're done.
                    break;
                }
            }
        }

        return bytes;
    }

    GMDLL char* DLLRSASignBuffer(const int* buffer, double length, char* priv) {
        vector<char*> tokens = tokenify(priv, (char*)"|");

        AutoSeededRandomPool rng;

        Integer n(tokens[0]), e(tokens[1]), d(tokens[2]);

        RSA::PrivateKey privKey;
        privKey.Initialize(n, e, d);

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

        string signature;

        // Sign and Encode
        RSASSA_PKCS1v15_SHA_Signer signer(privKey);

        VectorSource ss1(convertToBytes(buffer, length), true,
            new SignerFilter(rng, signer,
                new StringSink(signature)
            ) // SignerFilter
        ); // StringSource

        // Awful Hack
        // We can't return the string as-is because it may contain null bytes, which will
        // cause the data to be truncated. So convert the bytes to hex strings and parse
        // on GMS2's side.
        return toCharArray(charsToHex(signature));
    }

    GMDLL double DLLRSAVerifyBuffer(const int* buffer, double length, char* pub) {
        vector<char*> tokens = tokenify(pub, (char*)"|");

        AutoSeededRandomPool rng;

        Integer n(tokens[0]), e(tokens[1]);

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

        // Verify and Recover
        RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

        try {
            vector<byte> bytes = convertToBytes(buffer, length);

            VectorSource ss2(bytes, true,
                new SignatureVerificationFilter(
                    verifier, NULL,
                    SignatureVerificationFilter::THROW_EXCEPTION
                ) // SignatureVerificationFilter
            ); // StringSource
        }
        catch (SignatureVerificationFilter::SignatureVerificationFailed err) {
            return 0;
        }

        return 1;
    }
}