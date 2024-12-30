# Monobank API For Providers SDK for Dart

This package is unofficial

Implements cryptography and special methods to work Monobank Corp API (API for Providers).

API Documentation: [Monobank Open API for Providers](https://api.monobank.ua/docs/corporate.html)

See the main package [monobank_api](https://pub.dev/packages/monobank_api), as it contains 
the main logic for working with the Monobank API. This package only contains some additional
methods and classes for working with the Corp API and relevant cryptography. It is designed
to be used server-side.

## Usage

Quick example:

```dart
import 'dart:io';

import 'package:monobank_api/monobank_api.dart';
import 'package:monobank_api_corp/monobank_api_corp.dart';

void main() async {
  final keyPlainText = File('./keys/priv.key').readAsStringSync();
  final privateKey = MonoCorpRequestKey.getKeyFromPemFile(keyPlainText);

  final mono = MonoCorpAPI(privateKey);
  print((await mono.getCompany()).name);

  final user = mono.user(requestId: 'X-Request-Id');
  final client = await user.clientInfo();

  final statement = client.accounts
      .where((account) => account.balance.currency == Currency.code('USD'))
      .first
      .statement(
        DateTime.now().subtract(Duration(days: 180)),
        DateTime.now(),
      );

  await for (final item in statement.list(isReverseChronological: true)) {
    print('$item');
  }
}

```

See more examples in monobank_api package Example section.