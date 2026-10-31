// RUN: %clang_cc1 -std=c23 -Wimplicit-null-initialization -verify=warn -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -x c++ -std=c++20 -Wimplicit-null-initialization -verify=warn -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -std=c23 -Wnull-to-nonoptional -verify=conversion %s
// RUN: %clang_cc1 -std=c23 -verify=none %s
// none-no-diagnostics

// C23 constexpr pointer subobjects must have null values. Omitting the
// initializer for a non-optional pointer still requests a warning.
struct Required { int n; int *pointer; };
struct Optional { int n; _Optional int *pointer; };
struct Callback { int n; void (*callback)(void); };

constexpr int *empty_scalar = {}; // warn-warning {{implicitly initialized to null}}
constexpr struct Required record = {1}; // warn-warning {{implicitly initialized to null}}
constexpr int *array[3] = {}; // warn-warning {{implicitly initialized to null}}
constexpr int *partial[2] = {nullptr}; // warn-warning {{implicitly initialized to null}} conversion-warning {{null pointer constant converted}}
constexpr struct Callback callback = {1}; // warn-warning {{implicitly initialized to null}}
constexpr struct Optional optional_record = {1};
constexpr _Optional int *optional_array[3] = {};
constexpr _Optional int *optional_scalar = nullptr;

void local(void) {
  constexpr struct Required local_record = {1}; // warn-warning {{implicitly initialized to null}}
  constexpr int *local_array[2] = {}; // warn-warning {{implicitly initialized to null}}
  constexpr struct Optional local_optional = {1};
  (void)&local_record;
  (void)&local_array;
  (void)&local_optional;
}
