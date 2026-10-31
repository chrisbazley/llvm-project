// RUN: %clang_cc1 -std=c++20 -Wimplicit-null-initialization -verify %s
// expected-no-diagnostics

int value;
struct Constructed {
  int *const pointer;
  Constructed() : pointer(&value) {}
};
const Constructed constructed;
struct DefaultMember { int *const pointer = &value; };
const DefaultMember default_member;
struct Mutable { mutable int *pointer; Mutable() {} };
const Mutable mutable_member;
extern int *const declaration_only;
