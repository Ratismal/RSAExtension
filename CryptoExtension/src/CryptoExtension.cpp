// CryptoExtension.cpp : Defines the entry point for the application.
//

#include "../api/CryptoExtension.h"

#ifdef _WIN32
#define GMDLL extern "C" __declspec(dllexport)
#else
#define GMDLL
#endif

namespace CryptoExtension {

    GMDLL double DLLAddNumbers(double a, double b) {
        return a + b;
    }

    GMDLL char* DLLPrintSomething() {
        return (char*)"testing.";
    }

}