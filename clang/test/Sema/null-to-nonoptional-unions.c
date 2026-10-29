// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wnull-to-nonoptional -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-null-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// RUN: %clang_cc1 -x c++ -std=c++20 -fsyntax-only -Wnull-to-nonoptional -verify=warn %s
// RUN: %clang_cc1 -x c++ -std=c++20 -fsyntax-only -Wno-null-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -x c++ -std=c++20 -fsyntax-only -verify=none %s
// none-no-diagnostics

int value;
union PointerFirst {
  int *pointer; // warn-note 5 {{'pointer' declared here}}
  int number;
};

// With no explicit selection, only the first named member is initialized.
union PointerFirst empty = {}; // warn-warning {{pointer 'empty.pointer' implicitly initialized to null}}
union PointerFirst scalar = {.number = 1};
union PointerFirst nonnull = {.pointer = &value};
union PointerFirst empty_pointer = {.pointer = {}}; // warn-warning {{pointer 'empty_pointer.pointer' implicitly initialized to null}}

// Bare declarations remain outside the implicit-initialisation warning.
union PointerFirst reserved;
static union PointerFirst static_reserved;
thread_local union PointerFirst thread_reserved;

// Omitted unions and array elements use the first member too.
struct Parent { union PointerFirst choice; int number; };
struct Parent parent = {.number = 1}; // warn-warning {{pointer 'parent.choice.pointer' implicitly initialized to null}}
union PointerFirst array[3] = {{.number = 1}}; // warn-warning {{pointer 'array[1].pointer' implicitly initialized to null}}

void compound_literal(void) {
  (void)(union PointerFirst){}; // warn-warning {{pointer '<anonymous>.pointer' implicitly initialized to null}}
  (void)(union PointerFirst){.number = 1};
}

// A single-member union does not suppress the warning.
union Single {
  int *pointer; // warn-note {{'pointer' declared here}}
};
union Single single = {}; // warn-warning {{pointer 'single.pointer' implicitly initialized to null}}

// A scalar first member keeps inactive pointer members quiet.
union ScalarFirst { int number; int *pointer; };
union ScalarFirst scalar_first = {};
struct ScalarParent { union ScalarFirst choice; int number; };
struct ScalarParent scalar_parent = {.number = 1};

union OptionalFirst { _Optional int *pointer; int *inactive; };
union OptionalFirst optional_first = {};

// Unnamed bit-fields are not candidates for initialization.
union BitFieldFirst {
  unsigned : 1;
  int *pointer; // warn-note {{'pointer' declared here}}
  int number;
};
union BitFieldFirst bit_field = {}; // warn-warning {{pointer 'bit_field.pointer' implicitly initialized to null}}

// Diagnose omitted subobjects of the selected aggregate, not other members.
struct Required {
  int number;
  int *pointer; // warn-note 3 {{'pointer' declared here}}
};
union AggregateFirst { struct Required record; int *inactive; };
union AggregateFirst aggregate_first = {}; // warn-warning {{pointer 'aggregate_first.record.pointer' implicitly initialized to null}}
union AggregateFirst aggregate_scalar = {.inactive = &value};
union AggregateSelected { int number; struct Required record; int *inactive; };
union AggregateSelected aggregate_selected = {.record = {.number = 1}}; // warn-warning {{pointer 'aggregate_selected.record.pointer' implicitly initialized to null}}
union AggregateSelected aggregate_complete = {.record = {.pointer = &value}};
union AggregateSelected aggregate_default = {};
struct AggregateParent { union AggregateSelected choice; };
struct AggregateParent aggregate_parent = {.choice = {.record = {}}}; // warn-warning {{pointer 'aggregate_parent.choice.record.pointer' implicitly initialized to null}}

union ArrayFirst {
  int *pointers[3]; // warn-note {{'pointers' declared here}}
  int number;
};
union ArrayFirst array_first = {}; // warn-warning {{pointer 'array_first.pointers[0]' implicitly initialized to null}}
union ArrayFirst array_scalar = {.number = 1};

union FunctionFirst {
  void (*callback)(void); // warn-note {{'callback' declared here}}
  int number;
};
union FunctionFirst function_first = {}; // warn-warning {{pointer 'function_first.callback' implicitly initialized to null}}
union FunctionFirst function_scalar = {.number = 1};

// Anonymous union members retain the enclosing object's name.
struct Anonymous {
  union {
    int *pointer; // warn-note {{'pointer' declared here}}
    int number;
  };
};
struct Anonymous anonymous = {}; // warn-warning {{pointer 'anonymous.pointer' implicitly initialized to null}}
struct Anonymous anonymous_scalar = {.number = 1};

#ifdef __cplusplus
// A default member initializer selects its member rather than the first one.
union DefaultScalar { int *inactive; int number = 1; }; // warn-note {{'inactive' declared here}}
DefaultScalar default_scalar{};
DefaultScalar value_scalar = DefaultScalar();
DefaultScalar override_scalar = {.inactive = {}}; // warn-warning {{pointer 'override_scalar.inactive' implicitly initialized to null}}
struct DefaultScalarParent { DefaultScalar choice; };
DefaultScalarParent default_scalar_parent{};
union DefaultPointer { int number; int *pointer = &value; };
DefaultPointer default_pointer{};
DefaultPointer value_pointer = DefaultPointer();
union EmptyDefault {
  int number;
  int *pointer = {}; // warn-warning {{implicitly initialized to null}} warn-note {{'pointer' declared here}}
};
EmptyDefault empty_default{};
EmptyDefault value_default = EmptyDefault();
#endif
