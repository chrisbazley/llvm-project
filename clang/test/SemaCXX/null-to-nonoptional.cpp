// RUN: %clang_cc1 -std=c++20 -fsyntax-only -Wimplicit-null-initialization -verify=warn %s
// RUN: %clang_cc1 -std=c++20 -fsyntax-only -Wno-implicit-null-initialization -verify=none %s
// RUN: %clang_cc1 -std=c++20 -fsyntax-only -verify=none %s
// none-no-diagnostics

// Bare declarations are quiet regardless of storage duration.
int *static_pointer;
thread_local int *thread_pointer;
struct Bare { int *pointer; }; // warn-note {{'pointer' declared here}}
Bare static_record;

int value;
struct DefaultMember {
  int *pointer = &value;
};
struct Constructor {
  int *pointer;
  Constructor() : pointer(&value) {}
};

void value_initialisation() {
  int *pointer{}; // warn-warning {{pointer 'pointer' implicitly initialized to null; referenced type is not '_Optional'-qualified}}
  _Optional int *optional{};
  DefaultMember default_member{};
  Constructor constructor{};
  int *uninitialised;
  static Bare bare_record;
  static int *bare_pointer;
  thread_local int *bare_thread_pointer;
  Bare explicit_record{}; // warn-warning {{implicitly initialized to null}}

  (void)pointer;
  (void)optional;
  (void)default_member;
  (void)constructor;
  (void)&uninitialised;
}

