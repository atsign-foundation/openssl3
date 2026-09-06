/*
 * openssl3 shim: the only symbol this package adds on top of the OpenSSL
 * libcrypto ABI. Returns a JSON document describing how this exact binary was
 * built (OpenSSL version and commit, Configure target and arguments, compiler,
 * link flags). The string is generated at build time into
 * openssl3_build_info.c by tool/bin/build_openssl.dart.
 */
extern const char openssl3_build_info_json[];

#if defined(_WIN32)
#define OPENSSL3_EXPORT __declspec(dllexport)
#else
#define OPENSSL3_EXPORT __attribute__((visibility("default")))
#endif

OPENSSL3_EXPORT const char *openssl3_build_info(void) {
  return openssl3_build_info_json;
}
