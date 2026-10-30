// RUN: %clang_cc1 -std=c2y -Wnull-to-nonoptional -verify=conversion %s
// RUN: %clang_cc1 -std=c2y -Wimplicit-null-initialization -verify=initialization %s
// RUN: %clang_cc1 -std=c2y -Wnull-to-nonoptional -Wimplicit-null-initialization -verify=conversion,initialization %s
// RUN: %clang_cc1 -std=c2y -Wnull-to-nonoptional -Wimplicit-null-initialization -Wno-null-to-nonoptional -verify=initialization %s
// RUN: %clang_cc1 -std=c2y -Wnull-to-nonoptional -Wimplicit-null-initialization -Wno-implicit-null-initialization -verify=conversion %s
// RUN: %clang_cc1 -std=c2y  -verify=none %s
// RUN: %clang_cc1 -std=c2y -DPRAGMA_CONTROL -verify=pragma %s
// none-no-diagnostics

#ifndef PRAGMA_CONTROL
int *conversion = nullptr; // conversion-warning {{null pointer constant converted}}
struct Record {
  int n;
  int *p; // initialization-note {{'p' declared here}}
};
struct Record omitted = {1}; // initialization-warning {{implicitly initialized to null}}
int *empty = {}; // initialization-warning {{implicitly initialized to null}}
#else
#pragma clang diagnostic push
#pragma clang diagnostic warning "-Wnull-to-nonoptional"
#pragma clang diagnostic ignored "-Wimplicit-null-initialization"
int *conversion = nullptr; // pragma-warning {{null pointer constant converted}}
struct Record {
  int n;
  int *p; // pragma-note {{'p' declared here}}
};
struct Record quiet_omitted = {1};
#pragma clang diagnostic ignored "-Wnull-to-nonoptional"
#pragma clang diagnostic warning "-Wimplicit-null-initialization"
int *quiet_conversion = nullptr;
struct Record omitted = {1}; // pragma-warning {{implicitly initialized to null}}
#pragma clang diagnostic pop
int *default_conversion = nullptr;
struct Record default_omitted = {1};
#endif
