/*
 * openssl_assets shim: the only symbol this package adds on top of the OpenSSL
 * libcrypto ABI. Returns a JSON document describing how this exact binary was
 * built (OpenSSL version and commit, Configure target and arguments, compiler,
 * link flags). The string is generated at build time into
 * openssl_assets_build_info.c by tool/bin/build_openssl.dart.
 */
extern const char openssl_assets_build_info_json[];

#if defined(_WIN32)
#define OPENSSL_ASSETS_EXPORT __declspec(dllexport)
#else
#define OPENSSL_ASSETS_EXPORT __attribute__((visibility("default")))
#endif

OPENSSL_ASSETS_EXPORT const char *openssl_assets_build_info(void) {
  return openssl_assets_build_info_json;
}
