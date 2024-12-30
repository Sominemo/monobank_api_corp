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
