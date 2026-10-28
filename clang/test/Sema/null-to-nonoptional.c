// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wnull-to-nonoptional \
// RUN:   -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-null-to-nonoptional \
// RUN:   -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// none-no-diagnostics

#define NULL ((void *)0)

void accept(int *);
void accept_optional(_Optional int *);

int *global = nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
_Optional int *optional_global = nullptr;
int **nested = nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}

void assignments(int condition) {
  int *p;
  _Optional int *optional;

  p = 0; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  p = NULL; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  optional = 0;
  optional = nullptr;

  accept(nullptr); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept_optional(nullptr);

  p = condition ? p : nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  optional = condition ? optional : nullptr;

  (void)(int *)nullptr;
  (void)p;
  (void)optional;
}

int *return_null(void) {
  return nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
}

_Optional int *return_optional_null(void) {
  return nullptr;
}

int compare(int *p) {
  return p == nullptr;
}

// The warning does not alter the type of nullptr, in particular for _Generic.
static_assert(_Generic(nullptr, void *: 0, default: 1));
