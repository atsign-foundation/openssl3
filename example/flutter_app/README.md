# openssl3 Flutter example

Runs the same checks as `example/cli` on every Flutter platform and shows the
result. The build hook of `package:openssl3` bundles `libopenssl3_crypto` into
the app (Flutter wraps it in a framework on iOS/macOS).

    flutter run                     # any connected device / desktop
    flutter test integration_test   # same checks as a test, on a device

Inside this repository the hook takes the library from `../../out`; build it
first with `dart run tool/bin/build_openssl.dart <target>` from the repo root.
