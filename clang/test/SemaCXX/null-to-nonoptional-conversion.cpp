// RUN: %clang_cc1 -std=c++20 -fsyntax-only -Wnull-to-nonoptional -verify=warn %s
// RUN: %clang_cc1 -std=c++20 -fsyntax-only -Wnull-to-nonoptional -Wno-null-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c++20 -fsyntax-only -verify=none %s
// RUN: %clang_cc1 -std=c++20 -fsyntax-only -Wimplicit-null-initialization -verify=none %s
// none-no-diagnostics

int *global = nullptr; // warn-warning {{null pointer constant converted}}
_Optional int *optional_global = nullptr;
int *zero = 0; // warn-warning {{null pointer constant converted}}
int *gnu_null = __null; // warn-warning {{null pointer constant converted}}

struct Record {
  int *pointer;
};
Record designated = {.pointer = nullptr}; // warn-warning {{null pointer constant converted}}
Record positional = {nullptr}; // warn-warning {{null pointer constant converted}}
int *elements[] = {nullptr}; // warn-warning {{null pointer constant converted}}

struct MemberInitializer {
  int *pointer = nullptr; // warn-warning {{null pointer constant converted}}
};
struct Constructor {
  int *pointer;
  Constructor() : pointer(nullptr) {} // warn-warning {{null pointer constant converted}}
};
struct PointerConstructor {
  PointerConstructor(int *);
};
PointerConstructor constructed = nullptr; // warn-warning {{null pointer constant converted}}
struct OptionalPointerConstructor {
  OptionalPointerConstructor(_Optional int *);
};
OptionalPointerConstructor optional_constructed = nullptr;

void accept(int *);
void default_argument(int * = nullptr); // warn-warning {{null pointer constant converted}}
void accept_optional(_Optional int *);
void overloaded(int *);
void overloaded(decltype(nullptr));

void initializations() {
  int *copy = nullptr; // warn-warning {{null pointer constant converted}}
  int *direct(nullptr); // warn-warning {{null pointer constant converted}}
  int *list{nullptr}; // warn-warning {{null pointer constant converted}}
  int *copy_list = {nullptr}; // warn-warning {{null pointer constant converted}}
  int *const &reference = nullptr; // warn-warning {{null pointer constant converted}}
  auto allocated = new int *(nullptr); // warn-warning {{null pointer constant converted}}
  MemberInitializer member;
}

void assignments(int *p, bool condition) {
  p = nullptr; // warn-warning {{null pointer constant converted}}
  p = 0; // warn-warning {{null pointer constant converted}}
  accept(nullptr); // warn-warning {{null pointer constant converted}}
  accept_optional(nullptr);
  overloaded(nullptr);
  default_argument();

  p = condition ? p : nullptr; // warn-warning {{null pointer constant converted}}
  int *conditional = condition ? nullptr : p; // warn-warning {{null pointer constant converted}}
  accept(condition ? p : nullptr); // warn-warning {{null pointer constant converted}}
  p = condition ? (condition ? p : nullptr) : p; // warn-warning {{null pointer constant converted}}
  p = (void(), condition ? p : nullptr); // warn-warning {{null pointer constant converted}}
  p = p ?: nullptr; // warn-warning {{null pointer constant converted}}

  _Optional int *optional = condition ? p : nullptr;
  optional = condition ? nullptr : p;
  accept_optional(condition ? p : nullptr);
  accept_optional(condition ? (condition ? p : nullptr) : p);
  optional = p ?: nullptr;

  // Explicit pointer casts and comparisons remain quiet.
  p = (int *)nullptr;
  p = static_cast<int *>(nullptr);
  p = reinterpret_cast<int *>(0);
  p = (int *)(condition ? p : nullptr);
  p = static_cast<int *>(condition ? p : nullptr);
  accept(static_cast<int *>(nullptr));
  (void)(p == nullptr);
  (void)(nullptr != p);
  (void)((condition ? p : nullptr) == nullptr);
  (void)(condition ? p : nullptr);
}

int *return_null() {
  return nullptr; // warn-warning {{null pointer constant converted}}
}
int *return_conditional(int *p, bool condition) {
  return condition ? p : nullptr; // warn-warning {{null pointer constant converted}}
}
_Optional int *return_optional(int *p, bool condition) {
  return condition ? p : nullptr;
}

using Function = void();
Function *callback = nullptr; // warn-warning {{null pointer constant converted}}
_Optional Function *optional_callback = nullptr;
void accept_callback(Function *);
void accept_optional_callback(_Optional Function *);
void callbacks(Function *p, bool condition) {
  callback = nullptr; // warn-warning {{null pointer constant converted}}
  accept_callback(condition ? p : nullptr); // warn-warning {{null pointer constant converted}}
  accept_optional_callback(condition ? p : nullptr);
}

// Test the immediately referenced type, including typedefs.
using OptionalInt = _Optional int;
OptionalInt *optional_typedef = nullptr;
_Optional int **nested = nullptr; // warn-warning {{null pointer constant converted}}
int *_Optional *optional_nested = nullptr;

// Dependent initializations are diagnosed when instantiated.
template<class T> T *make_null() {
  return nullptr; // warn-warning {{null pointer constant converted}}
}
int *instantiate() {
  (void)make_null<_Optional int>();
  return make_null<int>(); // warn-note {{in instantiation of function template specialization}}
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnull-to-nonoptional"
int *pragma_quiet = nullptr;
#pragma clang diagnostic pop
int *pragma_restored = nullptr; // warn-warning {{null pointer constant converted}}
