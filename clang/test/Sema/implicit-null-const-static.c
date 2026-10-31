// RUN: %clang_cc1 -std=c2y -Wno-default-const-init -Wimplicit-null-initialization -verify=warn -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -std=c2y -Wno-default-const-init -Wnull-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c2y -Wno-default-const-init -verify=none %s
// none-no-diagnostics

int value;
int *const scalar; // warn-warning {{implicitly initialized to null}}
_Optional int *const optional;
const int *mutable_pointer;
int *mutable;
int *const array[3]; // warn-warning {{implicitly initialized to null}}
struct Record { int n; int *p; };
const struct Record record; // warn-warning {{implicitly initialized to null}}
struct Fixed { int *const p; } fixed; // warn-warning {{implicitly initialized to null}}
struct Nested { struct Record records[2]; };
const struct Nested nested; // warn-warning {{implicitly initialized to null}}
union PointerFirst { int *p; int n; };
const union PointerFirst active_pointer; // warn-warning {{implicitly initialized to null}}
union ScalarFirst { int n; int *p; };
const union ScalarFirst inactive_pointer;
extern int *const external_only;
int *const completed;
int *const completed = &value;
void local(void) {
  static int *const local_scalar; // warn-warning {{implicitly initialized to null}}
  static const struct Record local_record; // warn-warning {{implicitly initialized to null}}
  int *const automatic;
  const struct Record automatic_record;
  (void)&automatic;
  (void)&automatic_record;
  (void)&local_scalar;
  (void)&local_record;
}

// Thread storage follows the same rule in C.
thread_local int *const thread_pointer; // warn-warning {{implicitly initialized to null}}

typedef int *Pointer;
const Pointer typedef_pointer; // warn-warning {{implicitly initialized to null}}
int *const *mutable_outer;
int **const const_outer; // warn-warning {{implicitly initialized to null}}
void (*const callback)(void); // warn-warning {{implicitly initialized to null}}
struct Anonymous { union { int *p; int n; }; };
const struct Anonymous anonymous; // warn-warning {{implicitly initialized to null}}
_Optional int *const optional_array[2];
const _Atomic(int *) atomic_pointer; // warn-warning {{implicitly initialized to null}}
