/// Monobank Corp API SDK
///
/// Server side SDK for Monobank Open API for providers (Corp) with
/// higher request rate limits.
///
/// This library only implements required cryptography for the Corp API
/// and some methods unique to it. Most of the abstraction logic is located
/// in the `monobank_api` library.
library monobank_api_corp;

export 'src/mono_corp.dart';
export 'src/key.dart';
