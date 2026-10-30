// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wimplicit-null-initialization -verify=warn %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -Wno-implicit-null-initialization -verify=none %s
// RUN: %clang_cc1 -std=c2y -fsyntax-only -verify=none %s
// none-no-diagnostics

// Eligibility depends on supplying an initializer, not storage duration.
struct Required { int n; int *p; }; // warn-note 8 {{'p' declared here}}
struct Parent { int n; struct Required child; };
static struct Required reserved;
struct Required tentative;
struct Required tentative;
thread_local struct Required thread_reserved;

static struct Required empty = {}; // warn-warning {{implicitly initialized to null}}
static struct Required partial = {.n = 1}; // warn-warning {{implicitly initialized to null}}
static struct Parent nested = {.n = 1}; // warn-warning {{implicitly initialized to null}}

// File-scope compound literals are checked despite their static storage.
struct Required *literal = &(struct Required){}; // warn-warning {{implicitly initialized to null}}
struct Parent *nested_literal = &(struct Parent){.n = 1}; // warn-warning {{implicitly initialized to null}}

void local(void) {
  static struct Required bare;
  static thread_local struct Required thread_bare;
  struct Required automatic;
  static struct Required explicit_empty = {}; // warn-warning {{implicitly initialized to null}}
  struct Parent explicit_partial = {.n = 1}; // warn-warning {{implicitly initialized to null}}
  (void)(struct Required){.n = 1}; // warn-warning {{implicitly initialized to null}}
}
