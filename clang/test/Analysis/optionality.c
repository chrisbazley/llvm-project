// RUN: %clang_analyze_cc1 \
// RUN:   -std=c2y \
// RUN:   -Wno-unevaluated-expression \
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
//----
int *barton(_Optional typeof(int (void)) *pof)
{
  static typeof(pof()) retval;
  return &retval;
}
//----
typedef _Optional int *T1;
typedef T1 *T2;

int eros(T2 ppoi)
{
  T1 poi = *ppoi; // no recommended diagnostic
  return *poi;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
void pisces(const bool do_store)
{
  int i;
  _Optional int *poi = nullptr;

  if (do_store)
    poi = &i;

  if (do_store)
    *poi = 1; // possible diagnostic
}

//----
void phileas(_Optional int *const poi)
{
  bool do_store = true;

  if (!poi)
    do_store = false;

  if (do_store)
    *poi = 1; // possible diagnostic
}

//----
void fred(_Optional int *poi)
{
  int i;
  _Optional int *poi_2 = &i;

  for (i = 0; i < 200; ++i)
    poi_2 = (i * 13) % 2 ? &i : poi;

  *poi_2 = 1; // possible diagnostic
}

//----
void ram(int *);
void jim(_Optional int *poi)
{
  int i[16];

  poi = i;       // constrains poi to non-null
  *poi = 5;      // no recommended diagnostic
  ram(&*poi);    // no recommended diagnostic
  ram(&poi[15]); // no recommended diagnostic
}

//----
void hw(int *);

int sheila(_Optional int *poi)
{
  if (poi) {      // constrains poi to non-null
    *poi = 5;     // no recommended diagnostic
    hw(&*poi);    // no recommended diagnostic
    hw(&poi[15]); // no recommended diagnostic
  }

  for (; poi;) {  // constrains poi to non-null
    *poi = 6;     // no recommended diagnostic
    hw(&*poi);    // no recommended diagnostic
    hw(&poi[15]); // no recommended diagnostic
    break;
  }

  while (poi) {   // constrains poi to non-null
    *poi = 7;     // no recommended diagnostic
    hw(&*poi);    // no recommended diagnostic
    hw(&poi[15]); // no recommended diagnostic
    break;
  }

  if (!poi) {     // constrains poi to null
  } else {        // constrains poi to non-null
    *poi = 8;     // no recommended diagnostic
    hw(&*poi);    // no recommended diagnostic
    hw(&poi[15]); // no recommended diagnostic
  }

  return poi ? *poi : 0; // no recommended diagnostic
}

//----
static void fs(_Optional int *poi)
{
  *poi = 10; // possible diagnostic
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

void hazel(void)
{
  int i;
  fs(&i);
}

//----
static _Optional int *vdu(void)
{
  static int i;
  return &i;
}

void lynne(void)
{
  _Optional int *poi;
  poi = vdu();
  *poi = 2; // possible diagnostic
}

//----
void andy(_Optional int *poi)
{
  int *pi;

  pi = (int *)poi;          // does not constrain pi to non-null
  *(_Optional int *)pi = 2;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
void tina(int *pi)
{
  _Optional int *poi;

  poi = pi;  // does not constrain poi to non-null
  *poi = 10;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
int avon(int *pi)
{
  _Optional int *poi;

  // constrains pi to non-null on the fallthrough path
  if (!pi) return 0;

  poi = pi;    // non-null constraint is copied from pi to poi
  return *poi; // no recommended diagnostic
}

//----
_Optional int *volatile vpoi;
int brisbane(void)
{
  // does not constrain vpoi to non-null on either path
  if (!vpoi) return 0;

  return *vpoi; // FIXME: recommended diagnostic
}

//----
_Optional int *perth_poi;
void perth(_Optional int **ppoi)
{
  // constrains perth_poi to non-null on the fallthrough path
  if (!perth_poi) return;

  *perth_poi = 1;        // no recommended diagnostic
  *ppoi = nullptr; /* analysis discards non-null constraint
                    on perth_poi because *ppoi could alias perth_poi */
  *perth_poi = 2; // FIXME: recommended diagnostic
}

//----
void victoria(_Optional int **ppoi_1, _Optional int **ppoi_2)
{
  // constrains *ppoi_1 to non-null on the fallthrough path
  if (!*ppoi_1) return;

  **ppoi_1 = 1;      // no recommended diagnostic
  *ppoi_2 = nullptr; /* analysis discards non-null constraint
                      on *ppoi_1 because *ppoi_2 could
                      alias *ppoi_1 */
  **ppoi_1 = 2; // FIXME: recommended diagnostic
}

//----
_Optional int *darwin_poi;
void darwin(_Optional int **ppoi, _Optional int *upoi)
{
  // constrains darwin_poi to non-null on the fallthrough path
  if (!darwin_poi) return;

  *darwin_poi = 1;     // no recommended diagnostic
  *ppoi = upoi; /* analysis discards non-null constraint
                 on darwin_poi because *ppoi could alias darwin_poi */
  *darwin_poi = 2; // FIXME: recommended diagnostic
}

//----
void jordan(_Optional int *poi)
{
  _Optional int *poi_2, **ppoi = &poi_2;

  // constrains poi to non-null on the fallthrough path
  if (!poi) return;

  *poi = 1;        // no recommended diagnostic
  *ppoi = nullptr; /* non-null constraint on poi is unaffected
                    because *ppoi does not alias poi */
  *poi = 2;        // no recommended diagnostic
}

//----
void orlando(_Optional int **ppoi_1,
             _Optional int ** restrict ppoi_2)
{
  // constrains *ppoi_1 to non-null on the fallthrough path
  if (!*ppoi_1) return;

  **ppoi_1 = 1;      // no recommended diagnostic
  *ppoi_2 = nullptr; /* non-null constraint on *ppoi_1 is
                      unaffected because *ppoi_2 cannot
                      alias *ppoi_1 */
  **ppoi_1 = 2;      // no recommended diagnostic
}

//----
_Optional int *adelaide_poi;
void buxton(void); // has unknown side effects
void adelaide(void)
{
  // constrains adelaide_poi to non-null on the fallthrough path
  if (!adelaide_poi) return;

  *adelaide_poi = 1; // no recommended diagnostic
  buxton(); /* analysis discards non-null constraint on adelaide_poi
             because buxton could modify adelaide_poi */
  *adelaide_poi = 2;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
void bethany(void); // has unknown side effects
void lazarus(_Optional int **ppoi)
{
  // constrains *ppoi to non-null on the fallthrough path
  if (!*ppoi) return;

  **ppoi = 1; // no recommended diagnostic
  bethany();  /* analysis discards non-null constraint on *ppoi
               because bethany could modify *ppoi */
  **ppoi = 2; // FIXME: recommended diagnostic
}

//----
void morris(_Optional int **ppoi); // has unknown side effects
void aquarius(_Optional int *poi)
{
  // constrains poi to non-null on the fallthrough path
  if (!poi) return;

  *poi = 1;     // no recommended diagnostic
  morris(&poi); /* analysis discards non-null constraint on poi
                 because morris could modify poi */
  *poi = 2;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
void omega(_Optional int *const *ppoi); // unknown side effects
_Optional int **spinner_ppoi;
void spinner(_Optional int *poi)
{
  // constrains poi to non-null on the fallthrough path
  if (!poi) return;

  *poi = 1;    // no recommended diagnostic
  omega(&poi); // non-null constraint on poi is unaffected
  *poi = 2;    // no recommended diagnostic
  // FIXME: expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
  spinner_ppoi = &poi; // address of poi escapes this function
  omega(&poi); /* analysis discards constraint on poi because
                  omega could modify *ppoi (aka poi) */
  *poi = 3;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}
//----
_Optional int *chandler_poi;

void chandler(_Optional int **ppoi)
{
  int i;

  // constrains chandler_poi to non-null on the fallthrough path
  if (!chandler_poi) return;

  *chandler_poi = 1;   // no recommended diagnostic
  *ppoi = &i; // non-null constraint on chandler_poi is unaffected
  *chandler_poi = 2;   // no recommended diagnostic
}

//----
_Optional int *monica_poi;

void monica(_Optional int **ppoi, _Optional int *lpoi)
{
  // constrains monica_poi and lpoi to non-null on the fallthrough path
  if (!monica_poi || !lpoi) return;

  *monica_poi = 1;     // no recommended diagnostic
  *ppoi = lpoi; // non-null constraint on monica_poi is unaffected
  *monica_poi = 2;     // no recommended diagnostic
}

//----
void rachel(_Optional int **ppoi_1, _Optional int **ppoi_2)
{
  int i;

  // constrains *ppoi_1 to non-null on the fallthrough path
  if (!*ppoi_1) return;

  **ppoi_1 = 1;  // no recommended diagnostic
  *ppoi_2 = &i;  // non-null constraint on *ppoi_1 is unaffected
  **ppoi_1 = 2;  // no recommended diagnostic
}

//----
#if 0
// FIXME: Enable when [[reproducible]] is implemented.
_Optional int *phoebe_poi;
void ursula(void) [[reproducible]]; // no observable effects

void phoebe(void)
{
  // constrains phoebe_poi to non-null on the fallthrough path
  if (!phoebe_poi) return;

  *phoebe_poi = 1; // no recommended diagnostic
  ursula(); // non-null constraint on phoebe_poi is unaffected
  *phoebe_poi = 2; // no recommended diagnostic
}
#endif

//----
int autumn(_Optional int *poi)
{
  return poi[0];
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

int *brazil(_Optional int *poi)
{
  return &poi[0];
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
int autumn_checked(_Optional int *poi)
{
  if (poi) return poi[0];
  return 0;
}

int *brazil_checked(_Optional int *poi)
{
  if (poi) return &poi[0];
  return nullptr;
}

//----
int *foxton(_Optional int *poi)
{
  static typeof_unqual(poi[0]) i; // no recommended diagnostic
  return &i;
}

//----
struct S {
  int m;
};

int arabella(_Optional struct S *pos)
{
  return pos->m;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

int *albion(_Optional struct S *pos)
{
  return &pos->m;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----
int arabella_checked(_Optional struct S *pos)
{
  if (pos) return pos->m;
  return 0;
}

static int dummy;

int *albion_checked(_Optional struct S *pos)
{
  if (pos) return &pos->m;
  return &dummy;
}

//----
char *elsworth(_Optional struct S *pos)
{
  static char mbytes[sizeof(pos->m)]; //no recommended diagnostic
  return mbytes;
}

//----
_Optional int *electron(_Optional int *poi)
{
  poi++;
  // expected-warning@-1 {{Pointer to _Optional object is used by an increment or decrement operator without a preceding check for null}}
  return poi;
}

_Optional int *aberdeen(_Optional int *poi)
{
  poi--;
  // expected-warning@-1 {{Pointer to _Optional object is used by an increment or decrement operator without a preceding check for null}}
  return poi;
}

//----
_Optional int *electron_checked(_Optional int *poi)
{
  if (poi) poi++;
  return poi;
}

_Optional int *aberdeen_checked(_Optional int *poi)
{
  if (poi) poi--;
  return poi;
}

//----
char *newmarket(_Optional int *poi)
{
  static char ibytes[sizeof(poi--)]; // no recommended diagnostic
  return ibytes;
}

//----
_Optional int *stork(_Optional int *poi)
{
  return ++poi;
  // expected-warning@-1 {{Pointer to _Optional object is used by an increment or decrement operator without a preceding check for null}}
}

_Optional int *phoenix(_Optional int *poi)
{
  return --poi;
  // expected-warning@-1 {{Pointer to _Optional object is used by an increment or decrement operator without a preceding check for null}}
}

//----
_Optional int *stork_checked(_Optional int *poi)
{
  if (poi) return ++poi;
  return poi;
}

_Optional int *phoenix_checked(_Optional int *poi)
{
  if (poi) return --poi;
  return poi;
}

//----
char *cambridge(_Optional int *poi)
{
  static char ibytes[sizeof(++poi)]; // no recommended diagnostic
  return ibytes;
}

//----

void hawk(_Optional int *poi)
{
  *poi = 10;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

int heron(_Optional int *poi)
{
  return *poi;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

int *roadrunner(_Optional int *poi)
{
  return &*poi;
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
}

//----

void hawk_checked(_Optional int *poi)
{
  if (poi) *poi = 10;
}

int heron_checked(_Optional int *poi)
{
  if (poi) return *poi;
  return 0;
}

int *roadrunner_checked(_Optional int *poi)
{
  if (poi) return &*poi;
  return nullptr;
}

//----
typedef struct FILE FILE;
FILE *fopen(const char *, const char *);
int fflush(FILE *);

int opt_fflush(_Optional FILE *stream)
{
  return fflush((FILE *)stream);
}

#define FLUSH_ONE(STREAM) opt_fflush(&*(STREAM))
#define FLUSH_ALL()       opt_fflush(nullptr)

int main3(void)
{
  _Optional FILE *stream = fopen("test", "wb");
  FLUSH_ONE(stream);
  // expected-warning@-1 {{Pointer to _Optional object is dereferenced without a preceding check for null}}
  return 0;
}

//----
int medusa(_Optional const int *poi)
{
  return *(int *)poi; // no recommended diagnostic
}

//----
typedef __PTRDIFF_TYPE__ ptrdiff_t;

int *amber(_Optional int *poi)
{
  return poi + 1;
  // expected-warning@-1 {{Pointer to _Optional object is used by an additive operator without a preceding check for null}}
}

ptrdiff_t blue(_Optional int *poi, int *pi)
{
  return poi - pi;
  // expected-warning@-1 {{Pointer to _Optional object is used by an additive operator without a preceding check for null}}
}

int *green(_Optional int *poi)
{
  return poi - 0;
  // expected-warning@-1 {{Pointer to _Optional object is used by an additive operator without a preceding check for null}}
}

int *black(_Optional int *poi)
{
  return 0 + poi;
  // expected-warning@-1 {{Pointer to _Optional object is used by an additive operator without a preceding check for null}}
}

//----
int *amber_checked(_Optional int *poi)
{
  if (poi) return poi + 1;
  return &dummy;
}

ptrdiff_t blue_checked(_Optional int *poi, int *pi)
{
  if (poi) return poi - pi;
  return 0;
}

int *green_checked(_Optional int *poi)
{
  if (poi) return poi - 0;
  return &dummy;
}

int *black_checked(_Optional int *poi)
{
  if (poi) return 0 + poi;
  return &dummy;
}

//----
char *caldecote(_Optional int *poi)
{
  static char ibytes[sizeof(poi+1)]; // no recommended diagnostic
  return ibytes;
}

//----
int is_lt(_Optional int *poi, int *pi)
{
  return poi < pi;
  // expected-warning@-1 {{Pointer to _Optional object is used by a relational operator without a preceding check for null}}
}

int is_le(_Optional int *poi, int *pi)
{
  return poi <= pi;
  // expected-warning@-1 {{Pointer to _Optional object is used by a relational operator without a preceding check for null}}
}

int is_ge(_Optional int *poi, int *pi)
{
  return poi >= pi;
  // expected-warning@-1 {{Pointer to _Optional object is used by a relational operator without a preceding check for null}}
}

int is_gt(_Optional int *poi, int *pi)
{
  return poi > pi;
  // expected-warning@-1 {{Pointer to _Optional object is used by a relational operator without a preceding check for null}}
}

//----
int is_lt_checked(_Optional int *poi, int *pi)
{
  return poi && poi < pi;
}

int is_le_checked(_Optional int *poi, int *pi)
{
  return poi && poi <= pi;
}

int is_ge_checked(_Optional int *poi, int *pi)
{
  return poi && poi >= pi;
}

int is_gt_checked(_Optional int *poi, int *pi)
{
  return poi && poi > pi;
}

//----
int *coton(_Optional int *poi, int *pi)
{
  static typeof(poi < pi) result; // no recommended diagnostic
  return &result;
}
