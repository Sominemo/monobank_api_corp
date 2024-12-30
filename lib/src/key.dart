import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:monobank_api_corp/src/der_reader.dart';
import 'package:monobank_api_corp/src/type_utils.dart';

/// Monobank Corp API Request Key
///
/// This class is used to sign requests to Monobank API Corp edition, in
/// particular to generate X-Sign and X-Key-Id headers.
///
/// To use a key from a PEM file, use [getKeyFromPemFile] method.
/// To use a key from a hex string, use [fromHex] method.
class MonoCorpRequestKey {
  /// Private key raw scalar
  final Uint8List privateKeyScalar;

  /// Private key instance
  final PrivateKey privateKey;

  /// Create a new [MonoCorpRequestKey] from a private key scalar
  ///
  /// [privateKeyScalar] - private key scalar encoded as byte list
  MonoCorpRequestKey(this.privateKeyScalar)
      : privateKey = PrivateKey.fromBytes(getS256(), privateKeyScalar);

  /// Create a new [MonoCorpRequestKey] from a private key hex string
  ///
  /// [hex] - private key scalar encoded as hex string
  MonoCorpRequestKey.fromHex(String hex)
      : privateKeyScalar = hexToBytes(hex),
        privateKey = PrivateKey.fromHex(getS256(), hex);

  /// Create a new [MonoCorpRequestKey] from a private key DER bytes
  ///
  /// [key] - private key scalar encoded as DER bytes
  factory MonoCorpRequestKey.fromDerBytes(Uint8List key) {
    // python-ecdsa keys.py from_der
    final ec = getS256();

    final byteLength = (ec.bitSize + 7) >> 3;

    var keyRest = key;
    final keyResult = readSequence(keyRest);
    var keyData = keyResult.data;
    keyRest = keyResult.rest;

    if (keyRest.isNotEmpty) {
      throw Exception('Trailing junk after DER private key: $keyRest');
    }

    final keyVersionResult = readInteger(keyData);
    final keyVersion = keyVersionResult.data;
    keyData = keyVersionResult.rest;
    var isCurveConfirmed = false;

    if (keyVersion != 1) {
      throw Exception(
          'Expected version 1 at start of DER private key, got $keyVersion');
    }

    if (checkIfSequence(keyData)) {
      throw Exception('Did not expect AsymmetricKeyPackage');
    }

    final keyDataResult = readOctetString(keyData);
    var privateKeyData = keyDataResult.data;
    keyData = keyDataResult.rest;

    final curveCheckResult = readConstructed(keyData);
    final curveOid = curveCheckResult.data;
    final curveTag = curveCheckResult.alternativeData;

    if (curveTag != 0) {
      throw Exception('Expected tag 0 in DER private key, got $curveTag');
    }

    if (!_checkOid(curveOid)) {
      throw Exception(
          'Unexpected algorithm identifier $curveOid in DER private key');
    } else {
      isCurveConfirmed = true;
    }

    assert(isCurveConfirmed,
        'From the key, not sure if your key curve is SECP256K1');

    if (privateKeyData.length < byteLength) {
      privateKeyData = Uint8List.fromList(
          List.filled(byteLength - privateKeyData.length, 0)
            ..addAll(privateKeyData));
    }

    return MonoCorpRequestKey(privateKeyData);
  }

  /// Create a new [MonoCorpRequestKey] from a private key PEM file
  ///
  /// [keyPlainText] - private key PEM file string
  factory MonoCorpRequestKey.getKeyFromPemFile(String keyPlainText) {
    Uint8List? keyOid;
    try {
      keyOid = getPemSection(keyPlainText, 'EC PARAMETERS');
    } catch (e) {
      assert(e is Exception, 'Key file does not contain valid EC PARAMETERS');
    }

    if (keyOid != null && !_checkOid(keyOid)) {
      throw Exception(
          'Unexpected algorithm identifier. Expected SECP256K1 in EC PARAMETERS');
    }

    Uint8List key;
    try {
      key = getPemSection(keyPlainText, 'EC PRIVATE KEY');
    } on PemSectionNotFoundException {
      throw Exception(
          "Can't find EC PRIVATE KEY in key file. Did you supply a public key?");
    }

    return MonoCorpRequestKey.fromDerBytes(key);
  }

  /// Check if the key OID is SECP256K1
  static bool _checkOid(Uint8List? keyOid) {
    const referenceOid = [6, 5, 43, 129, 4, 0, 10];

    if (keyOid != null) {
      if (keyOid.length != referenceOid.length) {
        return false;
      }

      for (var i = 0; i < keyOid.length; i++) {
        if (keyOid[i] != referenceOid[i]) {
          return false;
        }
      }
    }

    return true;
  }

  /// Cached key ID
  String? _keyId;

  /// Get key ID
  ///
  /// The Key ID is used to identify the key in the Monobank API Corp
  String get keyId {
    _keyId ??= toKeyId(privateKey.publicKey);
    return _keyId!;
  }

  /// Generate a key ID from a public key
  ///
  /// [publicKey] - public key to generate key ID from
  ///
  /// Returns a key ID string
  ///
  /// The Key ID is a SHA1 hash of a compressed hex representation of the public
  /// key. Which, in turn, is two concatenated hex strings of X and Y coordinates
  /// of the public key.
  static String toKeyId(PublicKey publicKey) {
    final str = publicKey.toHex();
    return sha1.convert(hexToBytes(str)).toString();
  }

  /// Sign a message with the private key
  ///
  /// [message] - message to sign
  ///
  /// Returns a base64-encoded signature. The signature is generated by
  /// calculating SHA256 hash of the message and signing it with the private key
  /// using SECP256K1 curve.
  String sign(String message) {
    final secret = utf8.encode(message);
    final hash = sha256.convert(secret).bytes;

    final sig = signature(privateKey, hash);
    final result = base64.encoder.convert(sig.toCompact());

    return result;
  }
}
