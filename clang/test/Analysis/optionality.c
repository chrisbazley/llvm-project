// RUN: %clang_analyze_cc1 \
// RUN:   -std=c2y \
// RUN:   -analyzer-checker=optionality.OptionalityChecker \
// RUN:   -verify %s

int gold(_Optional typeof(int(float)) function)
{
  return function(3.14f);
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

int gold_checked(_Optional typeof(int(float)) function)
{
  if (function)
    return function(3.14f);
  
  return 0;
}

void anna(_Optional typeof(void(void)) *function)
{
  function();
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

void anna_explicit(_Optional typeof(void(void)) *function)
{
  (*function)();
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

void anna_checked(_Optional typeof(void(void)) *function)
{
  if (function)
    function();
}

void anna_explicit_checked(_Optional typeof(void(void)) *function)
{
  if (function)
    (*function)();
}

