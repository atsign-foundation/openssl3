/*
 * Minimal loader smoke test used by CI for targets where running Dart is not
 * practical (cross-compiled riscv64 under qemu, Android via adb, Alpine).
 *
 *   smoke_dlopen <path-to-libopenssl3_crypto>
 *
 * Loads the library, prints OpenSSL_version(), the embedded build info, and
 * checks that ML-KEM-768, ML-DSA-65, X25519 and AES-256-CTR can be fetched.
 * Exit code 0 on success.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long (*version_num_fn)(void);
typedef const char *(*version_fn)(int);
typedef const char *(*build_info_fn)(void);
typedef void *(*ctx_new_fn)(void *, const char *, const char *);
typedef void (*free_fn)(void *);

static int fail(const char *what) {
  fprintf(stderr, "FAIL: %s: %s\n", what, dlerror());
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <library>\n", argv[0]);
    return 64;
  }
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!lib) return fail("dlopen");

  version_num_fn version_num = (version_num_fn)dlsym(lib, "OpenSSL_version_num");
  version_fn version = (version_fn)dlsym(lib, "OpenSSL_version");
  build_info_fn build_info = (build_info_fn)dlsym(lib, "openssl3_build_info");
  ctx_new_fn pkey_ctx_new = (ctx_new_fn)dlsym(lib, "EVP_PKEY_CTX_new_from_name");
  free_fn pkey_ctx_free = (free_fn)dlsym(lib, "EVP_PKEY_CTX_free");
  ctx_new_fn cipher_fetch = (ctx_new_fn)dlsym(lib, "EVP_CIPHER_fetch");
  free_fn cipher_free = (free_fn)dlsym(lib, "EVP_CIPHER_free");
  if (!version_num || !version || !build_info || !pkey_ctx_new || !pkey_ctx_free ||
      !cipher_fetch || !cipher_free)
    return fail("dlsym");

  unsigned long num = version_num();
  printf("%s (0x%lx)\n%s\n", version(0), num, build_info());
  if ((num >> 20) != 0x305) {
    fprintf(stderr, "FAIL: expected OpenSSL 3.5.x\n");
    return 1;
  }

  const char *keys[] = {"ML-KEM-768", "ML-DSA-65", "X25519"};
  for (unsigned i = 0; i < 3; i++) {
    void *ctx = pkey_ctx_new(NULL, keys[i], NULL);
    if (!ctx) {
      fprintf(stderr, "FAIL: %s not available\n", keys[i]);
      return 1;
    }
    pkey_ctx_free(ctx);
    printf("ok %s\n", keys[i]);
  }
  const char *ciphers[] = {"AES-256-CTR", "AES-256-GCM"};
  for (unsigned i = 0; i < 2; i++) {
    void *c = cipher_fetch(NULL, ciphers[i], NULL);
    if (!c) {
      fprintf(stderr, "FAIL: %s not available\n", ciphers[i]);
      return 1;
    }
    cipher_free(c);
    printf("ok %s\n", ciphers[i]);
  }
  if (cipher_fetch(NULL, "RC4", NULL)) {
    fprintf(stderr, "FAIL: legacy RC4 unexpectedly available\n");
    return 1;
  }
  printf("ok legacy provider absent\n");
  dlclose(lib);
  return 0;
}
