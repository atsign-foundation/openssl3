import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:openssl3_example_flutter/smoke.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('bundled libcrypto works on this device', (tester) async {
    final result = runSmoke();
    expect(result.version, startsWith('OpenSSL 3.5.'));
    for (final MapEntry(key: name, value: ok) in result.checks.entries) {
      expect(ok, isTrue, reason: name);
    }
  });
}
