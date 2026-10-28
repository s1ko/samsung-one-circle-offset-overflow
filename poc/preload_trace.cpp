#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <new>

static void *g_file = nullptr;
static size_t g_want = 224;

void *operator new(std::size_t n)
{
  void *p = malloc(n ? n : 1);
  if (n == g_want && !g_file)
  {
    g_file = p;
    fprintf(stderr, "[shim] new(%zu) = %p (model file buffer)\n", n, p);
  }
  return p;
}

extern "C" void *memcpy(void *d, const void *s, size_t n)
{
  using fn_t = void *(*)(void *, const void *, size_t);
  static fn_t real = reinterpret_cast<fn_t>(dlsym(RTLD_NEXT, "memcpy"));
  if (g_file && (n == 64 || n == 16))
    fprintf(stderr, "[shim] memcpy n=%zu src=%p (file%+td) dst=%p\n", n, s,
            (const char *)s - (const char *)g_file, d);
  return real(d, s, n);
}
