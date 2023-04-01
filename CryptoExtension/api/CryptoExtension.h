// CryptoExtension.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#ifdef _WIN32
#define GMDLL extern "C" __declspec(dllexport)
#else
#define GMDLL
#endif

// TODO: Reference additional headers your program requires here.

namespace CryptoExtension {

    GMDLL double DLLAddNumbers(double a, double b);
    GMDLL char* DLLPrintSomething();

}