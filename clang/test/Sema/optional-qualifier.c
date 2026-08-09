// RUN: %clang_cc1 -std=c2y -fsyntax-only \
// RUN:   -Wno-unused-value -Wno-unevaluated-expression \
// RUN:   -verify-ignore-unexpected=note -verify %s

typedef __SIZE_TYPE__ size_t;
int puts(const char *);
void free(void *);
void *aligned_alloc(size_t, size_t);
char *getenv(const char *);
int strcmp(const char *, const char *);

char *unsafe_null = nullptr;
_Optional char *safe_null = nullptr;
const char *safe_literal = "hello";
_Optional char *safe_array[2] = {&(char){0}};

typedef _Optional int OptionalInt;
typedef int FunctionType(float);
typedef _Optional FunctionType OptionalFunction;

_Optional int bad_object; // expected-error {{object cannot have '_Optional' qualified type}}
_Optional typeof(int(float)) bad_function; // expected-error {{function cannot have '_Optional' qualified type}}

_Optional int *pointer_to_optional;
int *_Optional optional_pointer; // expected-error {{object cannot have '_Optional' qualified type}}

typedef int Array10[10];
typedef OptionalInt OptionalArray10[10];

struct GoodMembers {
  _Optional int *p;
  OptionalInt *p2;
  OptionalArray10 *pa;
  _Optional int (*pa2)[10];
  _Optional Array10 *poa;
  _Optional typeof(int(void)) *pf;
};

struct BadMembers {
  _Optional int a; // expected-error {{member cannot have '_Optional' qualified type}}
  OptionalInt b; // expected-error {{member cannot have '_Optional' qualified type}}
  OptionalArray10 c; // expected-error {{member cannot have '_Optional' qualified type}}
  _Optional Array10 d; // expected-error {{member cannot have '_Optional' qualified type}}
};

typeof(_Optional int) *typeof_optional;
static_assert(_Generic(typeof_optional, _Optional int *: 1, default: 0));
typeof_unqual(_Optional int) *typeof_plain;
static_assert(_Generic(typeof_plain, int *: 1, default: 0));

void good_pointer_parameter(_Optional int *);
void good_array_parameter(_Optional int a[2][3]);
static_assert(_Generic(good_array_parameter,
                       void (*)(_Optional int (*)[3]): 1, default: 0));
void good_function_parameter(_Optional typeof(int(float)) f);
static_assert(_Generic(good_function_parameter,
                       void (*)(_Optional typeof(int(float)) *): 1,
                       default: 0));

void bad_parameter(_Optional int x); // expected-error {{function parameter cannot have '_Optional' qualified type}}
void bad_pointer_parameter(int *_Optional x); // expected-error {{function parameter cannot have '_Optional' qualified type}}

#if 0
const int qualified_result(float);
volatile int qualified_result(float);
_Optional int qualified_result(float);
static_assert(_Generic(qualified_result, int (*)(float): 1, default: 0));
#endif

_Optional int *return_optional(float);
_Optional int (*return_optional_array(void))[10];
_Optional typeof(int(void)) *return_optional_function(void);

void compound_literals(void) {
  _Optional int *p = (_Optional int *){nullptr};
  p = &(_Optional int){0}; // expected-error {{compound literal cannot have '_Optional' qualified type}}
  (void)(_Optional int){0}; // expected-error {{compound literal cannot have '_Optional' qualified type}}
  (void)(int *_Optional){nullptr}; // expected-error {{compound literal cannot have '_Optional' qualified type}}
}

_Optional int *generic_pointer;
static_assert(_Generic(*generic_pointer, int: 1, default: 0));
static_assert(alignof(_Optional int) == alignof(int));
static_assert(sizeof(_Optional int) == sizeof(int));

struct Container { char bytes[64]; };
char *array_decay(_Optional const struct Container *p) {
  static char empty[] = "";
  if (!p) return empty;
  puts(p->bytes);
  static_assert(_Generic(p->bytes, const char *: 1, default: 0));
  return p->bytes; // expected-warning {{discards qualifiers}}
}

FunctionType function_impl;
FunctionType *function_decay(_Optional FunctionType *p) {
  if (!p) return &function_impl;
  static_assert(_Generic(*p, FunctionType *: 1, default: 0));
  return *p;
}

#define OPTIONAL_CAST(p) ((typeof(&*(p)))(p))
void free_optional_const(_Optional const char *p) {
  free(OPTIONAL_CAST(p)); // expected-warning {{discards qualifiers}}
}
void free_optional(_Optional char *p) { free(OPTIONAL_CAST(p)); }

typedef void VoidFunction(void);
VoidFunction void_function;
void qualifier_loss(void) {
  _Optional int *oi;
  int *i = oi; // expected-warning {{discards qualifiers}}
  _Optional VoidFunction *of = &void_function;
  VoidFunction *f = of; // expected-warning {{discards qualifiers}}
  (void)i; (void)f;
}

void increment_results(_Optional char *p) {
  if (!p) return;
  static_assert(_Generic(p++, _Optional char *: 1, default: 0));
  puts(p++); // expected-warning {{discards qualifiers}}
  static_assert(_Generic(++p, _Optional char *: 1, default: 0));
  puts(++p); // expected-warning {{discards qualifiers}}
  puts(p += 1); // expected-warning {{discards qualifiers}}
  puts(p = p + 1); // expected-warning {{discards qualifiers}}
  static_assert(_Generic(p--, _Optional char *: 1, default: 0));
  puts(p--); // expected-warning {{discards qualifiers}}
  static_assert(_Generic(--p, _Optional char *: 1, default: 0));
  puts(--p); // expected-warning {{discards qualifiers}}
}

int optional_strcmp(_Optional const char *a, _Optional const char *b) {
  if (!a) a = "";
  if (!b) b = "";
  static_assert(_Generic(&*a, const char *: 1, default: 0));
  return strcmp(&*a, &*b);
}

#define ALIGNED_ALLOC(T) (typeof(T) *)aligned_alloc(alignof(T), sizeof(T))
void allocation_types(void) {
  const int *ci = ALIGNED_ALLOC(const int);
  *ci = 0; // expected-error {{read-only}}
  _Optional char *oc = ALIGNED_ALLOC(_Optional char);
  getenv(oc); // expected-warning {{discards qualifiers}}
  double *d = ALIGNED_ALLOC(int); // expected-error {{incompatible pointer types}}
  (void)d;
}

int cast_optional = (_Optional int)3;
double cast_fraction = (_Optional int)3.1;

void arithmetic_types(_Optional char *p) {
  static_assert(_Generic(p + 1, char *: 1, default: 0));
  static_assert(_Generic(p - 1, char *: 1, default: 0));
}

void flow_does_not_remove_qualifier(_Optional int *p) {
  int value, *ordinary;
  if (p) {
    ordinary = p; // expected-warning {{discards qualifiers}}
    ordinary = (int *)p;
  }
  p = &value;
  ordinary = p; // expected-warning {{discards qualifiers}}
  (void)ordinary;
}

int _Optional = 43; // expected-error {{expected identifier}}
