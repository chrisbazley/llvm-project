// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wnull-to-nonoptional -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-null-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// none-no-diagnostics

#define NULL ((void *)0)

typedef void Callback(void);
void accept(int *);
void accept_optional(_Optional int *);
void accept_callback(Callback *);
void accept_optional_callback(_Optional Callback *);
void callback(void);
void side_effect(void);

struct Fields {
  int *required;
  _Optional int *optional;
};

// The null arm is permitted by each destination, even though the other arm
// points to a non-optional type. These reproduce the SFEditor CI warnings.
_Optional int *optional_destinations(int condition, int other, int *p, int *q) {
  _Optional int *initial = condition ? p : nullptr;
  initial = condition ? NULL : p;
  initial = condition ? p : 0;
  initial = condition ? p : (other ? q : nullptr);
  initial = condition ? (other ? nullptr : p) : q;
  initial = (side_effect(), condition ? p : nullptr);
  initial = p ?: nullptr;
  accept_optional(condition ? p : NULL);
  struct Fields fields = {.required = p, .optional = condition ? p : nullptr};
  (void)fields;
  (void)initial;
  return condition ? p : nullptr;
}

// The same null arms must still warn when converted to a non-optional target.
int *required_destinations(int condition, int other, int *p, int *q) {
  int *initial = condition ? p : nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? NULL : p; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? p : 0; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? p : (other ? q : nullptr); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? (other ? nullptr : p) : q; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = (side_effect(), condition ? p : nullptr); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = p ?: nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept(condition ? p : NULL); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept(_Generic(condition, int: condition ? p : nullptr)); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept(_Generic(condition, int: p, default: condition ? p : nullptr));
  accept(__builtin_choose_expr(1, p, condition ? p : nullptr));
  struct Fields fields = {.required = condition ? p : nullptr}; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? (other ? p : nullptr) : (other ? q : nullptr); // warn-warning 2 {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  (void)fields;
  (void)initial;
  return condition ? nullptr : p; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
}

_Optional Callback *optional_callbacks(int condition, Callback *p) {
  _Optional Callback *initial = condition ? callback : nullptr;
  initial = condition ? nullptr : p;
  accept_optional_callback(condition ? p : NULL);
  (void)initial;
  return condition ? p : nullptr;
}

Callback *required_callbacks(int condition, Callback *p) {
  Callback *initial = condition ? callback : nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  initial = condition ? nullptr : p; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept_callback(condition ? p : NULL); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  (void)initial;
  return condition ? p : nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
}

// Respect explicit pointer casts around a null value, an arm or the whole
// expression. An explicit cast on one arm does not suppress the other arm.
void explicit_casts(int condition, int other, int *p) {
  int *initial = condition ? p : (int *)nullptr;
  initial = (int *)(condition ? p : nullptr);
  initial = condition ? (int *)(other ? p : nullptr) : p;
  initial = condition ? (int *)nullptr : (other ? p : nullptr); // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
  accept((int *)(condition ? p : NULL));
  accept_callback(condition ? callback : (Callback *)nullptr);
  (void)initial;
}

// Conditional conversions alone, including discarded comma operands and null
// comparisons, do not impose a non-optional destination on a null arm.
void no_pointer_destination(int condition, int *p) {
  (void)(condition ? p : nullptr);
  (void)((condition ? p : NULL) == nullptr);
  (void)((condition ? nullptr : p) != nullptr);
  accept(((void)(condition ? p : nullptr), p));
}

// Preserve the existing conditional-expression types and _Generic selection.
void unchanged_types(int condition, int *p, _Optional int *optional) {
  static_assert(_Generic(condition ? p : nullptr, int *: 1, default: 0));
  static_assert(_Generic(condition ? NULL : p, int *: 1, default: 0));
  static_assert(_Generic(condition ? optional : nullptr,
                         _Optional int *: 1, default: 0));
}

// A nullptr_t-valued conditional still requires just one null conversion.
int *null_result(int condition) {
  return condition ? nullptr : nullptr; // warn-warning {{null pointer constant converted to a pointer whose referenced type is not '_Optional'-qualified}}
}
