// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wnull-to-nonoptional -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-null-to-nonoptional -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// none-no-diagnostics

int value;
void callback(void);
typedef void Callback(void);
typedef int *Pointer;
struct Required { int n; int *p; }; // warn-note 7 {{'p' declared here}}
struct Optional { int n; _Optional int *p; };
struct Nested { struct Required s; int *a[3]; }; // warn-note 3 {{'a' declared here}}
union Choice { int *p; int n; };
struct WithUnion { union Choice u; int n; };
struct Flexible { int n; int *a[]; };
struct AnonymousUnion { union { int *p; int n; }; int other; };

// Declarations without initializers do not request diagnostic checking,
// including tentative definitions, static locals and thread-local objects.
int *global;
int *global;
static int *internal;
thread_local int *thread;
void (*function)(void);
_Optional int *optional;
_Optional Callback *optional_function;
_Atomic(int *) atomic_pointer;
int **outer;
_Optional int **inner;
int * _Optional *optional_outer;
int *array[1000000];
struct Required record;
struct Nested nested;
struct Optional optional_record;
union Choice choice;
struct WithUnion with_union;
struct AnonymousUnion anonymous_union;
struct Flexible flexible;
extern int *declaration_only;
int *completed;
int *completed = &value;

int *scalar_empty = {}; // warn-warning {{implicitly initialized to null}}
int *empty[3] = {}; // warn-warning {{implicitly initialized to null}}
int *partial[3] = {&value}; // warn-warning {{implicitly initialized to null}}
int *hole[3] = {[2] = &value}; // warn-warning {{implicitly initialized to null}}
int *complete[2] = {&value, &value};
_Optional int *optional_array[3] = {};
struct Required empty_record = {}; // warn-warning {{implicitly initialized to null}}
struct Required partial_record = {1}; // warn-warning {{implicitly initialized to null}}
struct Required designated_record = {.n = 1}; // warn-warning {{implicitly initialized to null}}
struct Required complete_record = {.p = &value};
struct Nested empty_nested = {}; // warn-warning 2 {{implicitly initialized to null}}
struct Nested designated_nested = {.s.p = &value}; // warn-warning {{implicitly initialized to null}}
struct Required records[2] = {{.p = &value}}; // warn-warning {{implicitly initialized to null}}
union Choice empty_union = {};
union Choice scalar_union = {.n = 1};
struct WithUnion empty_with_union = {};
struct AnonymousUnion empty_anonymous_union = {};
struct Flexible empty_flexible = {};

void local(int n) {
  int *uninitialised;
  struct Required uninitialised_record;
  static int *local_static;
  static int *initialised_static = &value;
  int *local_array[3] = {&value}; // warn-warning {{implicitly initialized to null}}
  struct Nested local_nested = {}; // warn-warning 2 {{implicitly initialized to null}}
  struct Optional local_optional = {};
  union Choice local_union = {};
  (void)(struct Required){}; // warn-warning {{implicitly initialized to null}}
  (void)(int *[2]){}; // warn-warning {{implicitly initialized to null}}
  int *vla[n] = {}; // warn-warning {{implicitly initialized to null}}
}

// Explicit null initialisers retain the existing diagnostic, without an
// additional warning about the same subobject's implicit initialisation.
int *explicit_null = nullptr; // warn-warning {{null pointer constant converted}}
int *explicit_array[1] = {0}; // warn-warning {{null pointer constant converted}}
union Choice explicit_union = {.p = nullptr}; // warn-warning {{null pointer constant converted}}

