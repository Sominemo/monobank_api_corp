import 'dart:typed_data';

/// Convert bytes to integer
int bytesToInt(Uint8List bytes) {
  int result = 0;

  for (final byte in bytes) {
    result = (result << 8) | (byte & 0xff);
  }
  return result;
}

/// Convert integer to bytes
Uint8List hexToBytes(String hex) {
  final result = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    result.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(result);
}

/// Convert bytes to hex
String bytesToHex(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
}
