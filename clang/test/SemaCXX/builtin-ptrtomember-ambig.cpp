// RUN: %clang_cc1 -fsyntax-only -verify %s -std=c++11

struct A {};

struct R {
    operator const A*();
};


struct B  : R {
    operator A*();
};

struct C : B {

};


void foo(C c, int A::* pmf) {
	int i = c->*pmf; 	// expected-error {{use of overloaded operator '->*' is ambiguous}} \
  // expected-note 16 {{built-in candidate operator->*}}
}

