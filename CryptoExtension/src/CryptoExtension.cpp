// CryptoExtension.cpp : Defines the entry point for the application.
//

#include "../api/CryptoExtension.h"

#include <iostream>

using namespace CryptoPP;
using namespace std;

namespace CryptoExtension {

    GMDLL double DLLAddNumbers(double a, double b) {
        return a + b;
    }

    GMDLL char* DLLPrintSomething() {
        return (char*)"testing.";
    }

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

        ///////////////////////////////////////
        // Create Keys
        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        return (char*)"wow!";
    }

    char* toCharArray(string input) {
        char* array = new char[input.length() + 1];
        input.copy(array, input.length() + 1);
        return array;
        /*
        const int length = input.length();
        char* char_array = new char[int(length) + 1];

        // copying the contents of the
        // string to char array
        strcpy(char_array, input.c_str());
        return (char*)char_array;
        */
    }

    GMDLL char* DLLRSASign(char* input, char* _n, char* _e, char* _d) {
        AutoSeededRandomPool rng;

        Integer n(_n), e(_e), d(_d);

        RSA::PrivateKey privKey;
        privKey.Initialize(n, e, d);

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

        string message(input), signature;

        // Sign and Encode
        RSASSA_PKCS1v15_SHA_Signer signer(privKey);

        StringSource ss1(message, true,
            new SignerFilter(rng, signer,
                new StringSink(signature)
            ) // SignerFilter
        ); // StringSource

        return toCharArray(signature);
    }

    vector<char*> tokenify(char* input, char* delimiter) {
        vector<char*> v;

        char* chars = strtok(input, delimiter);
        while (chars) {
            v.push_back(chars);
            chars = strtok(NULL, delimiter);
        }

        return v;
    }

    char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F' };

    std::string charToHex(char const ch) {
        std::string str;
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
        return str;
    }

    std::string byte_2_str(char* bytes, int size) {
        std::string str;
        for (int i = 0; i < size; ++i) {
            const char ch = bytes[i];
            str.append(&hex[(ch & 0xF0) >> 4], 1);
            str.append(&hex[ch & 0xF], 1);
            str.append(" ");
        }
        return str;
    }

    vector<byte> convertToBytes(const int* buffer, double length) {
        vector<byte> bytes;

        int byteCount = 0;
        int limit = length / 4;
        int mod = int(length) % 4;
        if (mod > 0) {
            limit = (length + (4 - mod)) / 4;
        }

        for (int i = 0; i < limit; i++) {
            unsigned char b[4];
            unsigned long n = buffer[i];
            b[0] = (n >> 24) & 0xFF;
            b[1] = (n >> 16) & 0xFF;
            b[2] = (n >> 8) & 0xFF;
            b[3] = n & 0xFF;

            for (int j = 0; j < 4; j++) {
                int index = 3 - j;

                bytes.push_back(b[j]);

                cout << "Added byte " << byteCount << " " <<  charToHex(b[3 - j]) << " " << b[3 - j] << endl;

                if (++byteCount >= length) {
                    break;
                }
            }
        }

        return bytes;
    }

    GMDLL char* DLLRSASignBuffer(const int* buffer, double length, char* priv) {
        vector<char*> tokens = tokenify(priv, "|");

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

        return toCharArray(byte_2_str(toCharArray(signature), signature.length()));
    }

    GMDLL double DLLRSAVerifyBuffer(const int* buffer, double length, char* pub) {
        vector<char*> tokens = tokenify(pub, "|");

        // cout << "Starting verify." << endl;

        AutoSeededRandomPool rng;

        Integer n(tokens[0]), e(tokens[1]);

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

        // cout << "finished making keys" << endl;


        // Verify and Recover
        RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

        // cout << "verifying." << endl;

        try {
            // cout << "h." << endl;

            vector<byte> bytes = convertToBytes(buffer, length);

            /*
            byte* messageBytes = new byte[length - 384];
            byte* signatureBytes = new byte[384];

            int offset = length - 384;

            for (int i = 0; i < length; i++) {
                if (i < offset) {
                    messageBytes[i] = bytes[i];
                    cout << "Added message byte " << i << " " << charToHex(bytes[i]) << " " << bytes[i] << endl;
                }
                else {
                    signatureBytes[i - offset] = bytes[i];
                    cout << "Added signature byte " << i - offset << " " << charToHex(bytes[i]) << " " << bytes[i] << endl;
                }
            }
            */

            VectorSource ss2(bytes, true,
                new SignatureVerificationFilter(
                    verifier, NULL,
                    SignatureVerificationFilter::THROW_EXCEPTION
                ) // SignatureVerificationFilter
            ); // StringSource

            // cout << "hh." << endl;
        }
        catch (SignatureVerificationFilter::SignatureVerificationFailed err) {
            // cout << "error: " << err.what() << endl;
            

            return 0;
        }

        // cout << "done." << endl;

        return 1;
    }

    GMDLL double DLLRSAVerify(char* input, char* signature, char* _n, char* _e) {
        AutoSeededRandomPool rng;

        Integer n(_n), e(_e);

        RSA::PublicKey pubKey;
        pubKey.Initialize(n, e);

        string message(input);

        // Verify and Recover
        RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

        StringSource ss2(message, true,
            new SignatureVerificationFilter(
                verifier, NULL,
                SignatureVerificationFilter::THROW_EXCEPTION
            ) // SignatureVerificationFilter
        ); // StringSource

        return 1;
    }

}