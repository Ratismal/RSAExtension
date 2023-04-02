// CryptoExtension.cpp : Defines the entry point for the application.
//

#include "../api/RSAExtension.h"

#include <iostream>

namespace RSAExtension {
    GMDLL char* DLLTest() {
        return (char*)"testing.";
    }

    // Generate the key components and outputs a set of macros to console that can be used within GMS2
    GMDLL char* DLLGenerateKeys() {
        return (char*)"wow!";
    }

    GMDLL char* DLLRSASignBuffer(const int* buffer, double length, char* priv) {
        return (char*)"wow!";
    }

    GMDLL double DLLRSAVerifyBuffer(const int* buffer, double length, char* pub) {
        return 1;
    }
}