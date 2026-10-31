// RUN: %clang_cc1 -x c++ -std=c++20 -Wno-c99-designator -fsyntax-only -Wimplicit-null-initialization -verify=warn %s
// RUN: %clang_cc1 -x c++ -std=c++20 -Wno-c99-designator -fsyntax-only -Wno-implicit-null-initialization -verify=none %s
// RUN: %clang_cc1 -x c++ -std=c++20 -Wno-c99-designator -fsyntax-only -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wimplicit-null-initialization -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-implicit-null-initialization -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// none-no-diagnostics

int value;
struct Leaf {
  int *next; // warn-note 6 {{'next' declared here}}
};
struct Outer {
  struct Leaf left;
  struct Leaf right;
  int *slots[4]; // warn-note 2 {{'slots' declared here}}
};

// The same member declaration can belong to several distinct subobjects.
struct Outer object = {}; // warn-warning {{pointer 'object.left.next' implicitly initialized to null; referenced type is not '_Optional'-qualified}} warn-warning {{pointer 'object.right.next' implicitly initialized to null}} warn-warning {{pointer 'object.slots[0]' implicitly initialized to null}}

// Report an actually omitted element, even when later elements are explicit.
struct Outer partial = {.left.next = &value, .slots[1] = &value}; // warn-warning {{pointer 'partial.right.next' implicitly initialized to null}} warn-warning {{pointer 'partial.slots[0]' implicitly initialized to null}}
struct Leaf records[3] = {[1].next = &value}; // warn-warning {{pointer 'records[0].next' implicitly initialized to null}}
int *array[3] = {[1] = &value}; // warn-warning {{pointer 'array[0]' implicitly initialized to null}}

// Static storage without an initializer is deliberately outside the warning.
struct Outer static_object;
int *single;

// Array filler diagnostics need a representative index at each level.
struct Leaf multidimensional[2][3] = {}; // warn-warning {{pointer 'multidimensional[0][0].next' implicitly initialized to null}}

struct {
  struct {
    int *pointer; // warn-note {{'pointer' declared here}}
  };
} anonymous_member = {}; // warn-warning {{pointer 'anonymous_member.pointer' implicitly initialized to null}}

void compound_literal(void) {
  (void)(struct Leaf){}; // warn-warning {{pointer '<anonymous>.next' implicitly initialized to null}}
}

// Array elements can also be pointer objects, without a member declaration.
void local_array(void) {
  int *elements[4] = {[0] = &value, [2] = &value}; // warn-warning {{pointer 'elements[1]' implicitly initialized to null}}
  (void)elements;
}

