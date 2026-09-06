import 'package:flutter/material.dart';

import 'smoke.dart';

void main() => runApp(const OpenSsl3ExampleApp());

class OpenSsl3ExampleApp extends StatelessWidget {
  const OpenSsl3ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'openssl3 example',
      theme: ThemeData(colorSchemeSeed: Colors.teal),
      home: const SmokePage(),
    );
  }
}

class SmokePage extends StatefulWidget {
  const SmokePage({super.key});

  @override
  State<SmokePage> createState() => _SmokePageState();
}

class _SmokePageState extends State<SmokePage> {
  SmokeResult? _result;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _run();
  }

  void _run() {
    try {
      setState(() => _result = runSmoke());
    } catch (e) {
      setState(() => _error = e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('package:openssl3 smoke test')),
      body: _error != null
          ? Center(child: Text('Failed: $_error', key: const Key('error')))
          : result == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Text(
                  result.version,
                  key: const Key('version'),
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                if (result.target != null)
                  Text('bundled build for ${result.target}'),
                const SizedBox(height: 16),
                for (final MapEntry(key: name, value: ok)
                    in result.checks.entries)
                  ListTile(
                    leading: Icon(
                      ok ? Icons.check_circle : Icons.error,
                      color: ok ? Colors.green : Colors.red,
                    ),
                    title: Text(name),
                  ),
                const SizedBox(height: 16),
                Text(
                  result.allPassed ? 'All checks passed' : 'Some checks FAILED',
                  key: const Key('summary'),
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                TextButton(onPressed: _run, child: const Text('Run again')),
              ],
            ),
    );
  }
}
