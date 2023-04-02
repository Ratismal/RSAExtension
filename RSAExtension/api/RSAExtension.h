// CryptoExtension.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#ifdef _WIN32
#define GMDLL extern "C" __declspec(dllexport)
#else
#define GMDLL extern "C"
#endif



// TODO: Reference additional headers your program requires here.

namespace RSAExtension {

    GMDLL char* DLLTest();
    GMDLL char* DLLGenerateKeys();
    GMDLL char* DLLRSASignBuffer(const int* buffer, double length, char* priv);
    GMDLL double DLLRSAVerifyBuffer(const int* buffer, double length, char* pub);

}