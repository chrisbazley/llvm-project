// RUN: %clang_cc1 -std=c2y -verify -verify-ignore-unexpected=note %s
#pragma clang diagnostic warning "-Wimplicit-null-initialization"
int *const early_loud; // expected-warning {{implicitly initialized to null}}
void local(void) {
  static int *const loud; // expected-warning {{implicitly initialized to null}}
  (void)&loud;
}
#pragma clang diagnostic ignored "-Wimplicit-null-initialization"
int *const late_quiet;
void quiet(void) { static int *const pointer; (void)&pointer; }
#pragma clang diagnostic warning "-Wimplicit-null-initialization"
int *const final_loud; // expected-warning {{implicitly initialized to null}}
#pragma clang diagnostic ignored "-Wimplicit-null-initialization"
