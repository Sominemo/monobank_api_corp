// largely based on python-ecdsa library, see der.py
import 'dart:convert';
import 'dart:typed_data';
import 'type_utils.dart';

/// DER Reader Exception
///
/// Exception thrown when an error occurs while reading DER data
class DerReaderException implements Exception {
  /// Error message
  final String message;

  /// Create a new instance of [DerReaderException]
  DerReaderException(this.message);

  @override
  String toString() {
    return 'DerReaderException: $message';
  }
}

/// PEM Section Not Found Exception
///
/// Exception thrown when a PEM section is not found. See message for details.
class PemSectionNotFoundException extends DerReaderException {
  /// Create a new instance of [PemSectionNotFoundException]
  PemSectionNotFoundException(super.message);

  @override
  String toString() {
    return 'PemSectionNotFoundException: $message';
  }
}

/// PEM read result
///
/// Result of reading a PEM section
///
/// T - type for primary data
/// U - type for alternative data, if any
class ReadResult<T, U> {
  /// Primary data
  final T data;

  /// Rest of the buffer that is not the primary data
  final Uint8List rest;

  /// Alternative data, if any
  final U? alternativeData;

  /// Create a new instance of [ReadResult]
  const ReadResult(this.data, this.rest, [this.alternativeData]);
}

/// Check if the buffer is a PEM sequence
bool checkIfSequence(Uint8List buffer) {
  return buffer.isNotEmpty && buffer[0] == 0x30;
}

/// Read a constructed type from the PEM buffer
ReadResult<Uint8List, int> readConstructed(Uint8List buffer) {
  if ((buffer[0] & 0xE0) != 0xA0) {
    throw DerReaderException('Signature is not a constructed type');
  }

  final tag = buffer[0] & 0x1F;
  final lengthResult = readLength(buffer.sublist(1));
  final length = lengthResult[0];
  final metaLength = lengthResult[1];
  final body = buffer.sublist(1 + metaLength, 1 + metaLength + length);
  final rest = buffer.sublist(1 + metaLength + length);

  return ReadResult(body, rest, tag);
}

/// Read a sequence from the PEM buffer
ReadResult<Uint8List, void> readSequence(Uint8List buffer) {
  if (buffer.isEmpty) {
    throw DerReaderException('Empty buffer does not encode a sequence');
  }

  if (buffer[0] != 0x30) {
    throw DerReaderException('Signature is not a sequence');
  }

  final List<int> lengthData = readLength(buffer.sublist(1));
  final int length = lengthData[0];
  final int metaLength = lengthData[1];

  if (length > buffer.length - 1 - metaLength) {
    throw DerReaderException('Length longer than the provided buffer');
  }

  final int endSeq = 1 + metaLength + length;
  final sequence = buffer.sublist(1 + metaLength, endSeq);
  final rest = buffer.sublist(endSeq);

  return ReadResult(sequence, rest);
}

/// Read an octet string from the PEM buffer
ReadResult<Uint8List, void> readOctetString(Uint8List buffer) {
  if (buffer[0] != 0x04) {
    throw DerReaderException('Invalid DER encoding: ${buffer[0]}');
  }

  final lengthResult = readLength(buffer.sublist(1));
  final length = lengthResult[0];
  final metaLength = lengthResult[1];

  final body = buffer.sublist(1 + metaLength, 1 + metaLength + length);
  final rest = buffer.sublist(1 + metaLength + length);

  return ReadResult(body, rest);
}

/// Read an object identifier from the PEM buffer
ReadResult<List<int>, void> readObject(Uint8List buffer) {
  if (buffer.isEmpty) {
    throw DerReaderException(
        'Empty buffer does not encode an object identifier');
  }

  if (buffer[0] != 0x06) {
    throw DerReaderException('Signature is not an object identifier');
  }

  final lengthResult = readLength(buffer.sublist(1));
  final length = lengthResult[0];
  final metaLength = lengthResult[1];
  var body = buffer.sublist(1 + metaLength, 1 + metaLength + length);
  final rest = buffer.sublist(1 + metaLength + length);

  if (body.isEmpty) {
    throw DerReaderException('Empty object identifier');
  }

  if (body.length != length) {
    throw DerReaderException(
        'Length of object identifier longer than the provided buffer');
  }

  final numbers = <int>[];
  while (body.isNotEmpty) {
    final result = readNumber(body);
    numbers.add(result.data);
    body = result.rest;
  }

  final n0 = numbers.removeAt(0);
  final first = n0 < 80 ? n0 ~/ 40 : 2;
  final second = n0 - (40 * first);
  numbers.insert(0, first);
  numbers.insert(1, second);

  return ReadResult(numbers, rest);
}

/// Read a boolean from the PEM buffer
ReadResult<int, void> readInteger(Uint8List buffer) {
  if (buffer.isEmpty) {
    throw DerReaderException(
        'Empty string is an invalid encoding of an integer');
  }

  if (buffer[0] != 0x02) {
    throw DerReaderException('Signature is not an integer');
  }

  final lengthResult = readLength(buffer.sublist(1));
  final length = lengthResult[0];
  final metaLength = lengthResult[1];

  if (length > buffer.length - 1 - metaLength) {
    throw DerReaderException('Length longer than provided buffer');
  }

  if (length == 0) {
    throw DerReaderException('0-byte long encoding of integer');
  }

  final numberBytes = buffer.sublist(1 + metaLength, 1 + metaLength + length);
  final rest = buffer.sublist(1 + metaLength + length);

  if (numberBytes[0] >= 0x80) {
    throw DerReaderException('Negative integers are not supported');
  }

  if (length > 1 && numberBytes[0] == 0x00 && numberBytes[1] < 0x80) {
    throw DerReaderException(
        'Invalid encoding of integer, unnecessary zero padding bytes');
  }

  final number = bytesToInt(numberBytes);
  return ReadResult(number, rest);
}

/// Read a number from the PEM buffer
ReadResult<int, int> readNumber(Uint8List buffer) {
  var number = 0;
  var metaLength = 0;

  if (buffer[0] == 0x80) {
    throw DerReaderException('Non-minimal encoding of OID sub-identifier');
  }

  while (true) {
    if (metaLength >= buffer.length) {
      throw DerReaderException('ran out of length bytes');
    }

    number = (number << 7) | (buffer[metaLength] & 0x7F);
    final isLast = (buffer[metaLength] & 0x80) == 0;
    metaLength++;

    if (isLast) {
      break;
    }
  }

  return ReadResult(number, buffer.sublist(metaLength), metaLength);
}

/// Read a length from the PEM buffer
List<int> readLength(Uint8List buffer) {
  final int num = buffer[0];
  if (num < 0x80) {
    return [num, 1];
  }
  final int metaLength = num & 0x7F;
  if (metaLength == 0 || metaLength > buffer.length - 1) {
    throw DerReaderException('Invalid length encoding');
  }
  int length = 0;
  for (int i = 1; i <= metaLength; i++) {
    length = (length << 8) | buffer[i];
  }
  return [length, metaLength + 1];
}

/// Read a bit string from the PEM buffer
ReadResult<Uint8List, int> readBitString(Uint8List buffer,
    [int? expectUnused]) {
  if (buffer.isEmpty) {
    throw DerReaderException('Empty string does not encode a bit string');
  }

  if (buffer[0] != 0x03) {
    throw DerReaderException('Signature is not a bit string');
  }

  final lengthResult = readLength(buffer.sublist(1));
  final length = lengthResult[0];
  final metaLength = lengthResult[1];

  if (length == 0) {
    throw DerReaderException("Invalid length of bit string, can't be 0");
  }

  var body = buffer.sublist(1 + metaLength, 1 + metaLength + length);
  final rest = buffer.sublist(1 + metaLength + length);

  if (expectUnused != null) {
    final unused = body[0];
    if (unused < 0 || unused > 7) {
      throw DerReaderException('Invalid encoding of unused bits');
    }

    if (expectUnused != unused) {
      throw DerReaderException('Unexpected number of unused bits');
    }

    body = body.sublist(1);

    if (unused > 0 && body.isNotEmpty) {
      final last = body.last;
      if (last & ((1 << unused) - 1) != 0) {
        throw DerReaderException('Non-zero padding bits in bit string');
      }
    }
  }

  return ReadResult(body, rest);
}

/// Get list of PEM labels
///
/// Looks for lines that start with '-----BEGIN ' and end with '-----'
List<String> listPemLabels(String pem) {
  final labels = <String>[];
  final lines = LineSplitter.split(pem).map((line) => line.trim()).toList();
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('-----BEGIN ') && lines[i].endsWith('-----')) {
      labels.add(lines[i].substring(11, lines[i].length - 5));
    }
  }
  return labels;
}

/// Decode a PEM section
///
/// Decodes a PEM section from a string. The section is expected to be base64
/// encoded. Can ignore lines that start with '-----' and are empty.
Uint8List decodePemSection(String pemString) {
  final lines = pemString.split('\n');
  final base64Data =
      lines.where((line) => !line.startsWith('-----') && line.isNotEmpty);

  var base64DataString = '';

  for (final line in base64Data) {
    base64DataString += line.trim();
  }

  return base64.decode(base64DataString);
}

/// Get a PEM section by label name
Uint8List getPemSection(String pemString, String label) {
  final lines = pemString.split('\n');
  var inSection = false;
  final section = <String>[];
  for (final line in lines) {
    if (line.startsWith('-----BEGIN $label-----')) {
      assert(!inSection);
      inSection = true;
    } else if (line.startsWith('-----END $label-----')) {
      assert(inSection);
      inSection = false;
    } else if (inSection) {
      section.add(line);
    }
  }

  if (section.isEmpty) {
    throw PemSectionNotFoundException('PEM section $label not found');
  }

  return decodePemSection(section.join('\n'));
}
