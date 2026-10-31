// RUN: %clang_cc1 -std=c++20 -Wimplicit-null-initialization -verify=initialization %s
// RUN: %clang_cc1 -std=c++20 -Wnull-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c++20 -Wnull-to-nonoptional -Wimplicit-null-initialization -Wno-null-to-nonoptional -verify=initialization %s
// RUN: %clang_cc1 -std=c++20 -Wnull-to-nonoptional -Wimplicit-null-initialization -Wno-implicit-null-initialization -verify=none %s
// RUN: %clang_cc1 -std=c++20 -verify=none %s
// RUN: %clang_cc1 -std=c++20 -DPRAGMA_CONTROL -verify=pragma %s
// none-no-diagnostics

#ifndef PRAGMA_CONTROL
int *empty{}; // initialization-warning {{implicitly initialized to null}}
_Optional int *optional{};
int *bare;
#else
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wnull-to-nonoptional"
#pragma clang diagnostic ignored "-Wimplicit-null-initialization"
int *quiet{};
#pragma clang diagnostic warning "-Wimplicit-null-initialization"
#pragma clang diagnostic ignored "-Wnull-to-nonoptional"
int *loud{}; // pragma-warning {{implicitly initialized to null}}
#pragma clang diagnostic pop
int *default_quiet{};
#endif
