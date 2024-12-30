import 'package:monobank_api/monobank_api.dart';
import 'package:monobank_api_corp/src/key.dart';

/// Mono Corp Company Data
///
/// Data about a company registered in Mono Corp.
///
/// Returned by [MonoCorpAPI.getCompany]
class MonoCorpCompanyData {
  /// Public key
  final String pubKey;

  /// Company name
  final String name;

  /// Company permissions
  final Set<ClientPermission> permission;

  /// Company logo URL
  final String logo;

  /// Webhook URL
  final Uri? webhook;

  /// Create a new instance of [MonoCorpCompanyData]
  const MonoCorpCompanyData({
    required this.pubKey,
    required this.name,
    required this.permission,
    required this.logo,
    this.webhook,
  });

  /// Create a new instance of [MonoCorpCompanyData] from JSON
  factory MonoCorpCompanyData.fromJson(Map<String, dynamic> json) {
    return MonoCorpCompanyData(
      pubKey: json['pubkey'] as String,
      name: json['name'] as String,
      permission: ClientPermission.parse(json['permission'] as String),
      logo: json['logo'] as String,
      webhook: json['webhook'] != null
          ? Uri.tryParse(json['webhook'] as String)
          : null,
    );
  }

  /// Convert this instance of [MonoCorpCompanyData] to JSON
  Map<String, dynamic> toJson() {
    return {
      'pubkey': pubKey,
      'name': name,
      'permission': permission.map((e) => e.toString()).join(''),
      'logo': logo,
      'webhook': webhook?.toString(),
    };
  }
}

/// Mono Data Access Request
class MonoDataAccessRequest {
  /// Token request ID
  final String tokenRequestId;

  /// Full URL where the user can accept the request
  final Uri acceptUrl;

  /// Create a new instance of [MonoDataAccessRequest]
  const MonoDataAccessRequest({
    required this.tokenRequestId,
    required this.acceptUrl,
  });

  /// Create a new instance of [MonoDataAccessRequest] from JSON
  factory MonoDataAccessRequest.fromJson(Map<String, dynamic> json) {
    return MonoDataAccessRequest(
      tokenRequestId: json['tokenRequestId'] as String,
      acceptUrl: Uri.parse(json['acceptUrl'] as String),
    );
  }

  /// Convert this instance of [MonoDataAccessRequest] to JSON
  Map<String, dynamic> toJson() {
    return {
      'tokenRequestId': tokenRequestId,
      'acceptUrl': acceptUrl.toString(),
    };
  }
}

/// Mono Corp API methods for controlling the company
///
/// These methods are used to control the company registered in Mono Corp API.
///
/// See [MonoCorpAPI] for use.
mixin CorpControlMethods on API {
  /// Register a company in Mono Corp
  ///
  /// Returns the status of the registration or throws an error.
  Future<String> registration({
    required String pubKey,
    required String name,
    required String description,
    required String contactPerson,
    required String phone,
    required String email,
    required String logo,
  }) async {
    final data = await call(APIRequest('personal/auth/registration',
        methodId: 'personal/auth/registration',
        useAuth: true,
        data: {
          'pubkey': pubKey,
          'name': name,
          'description': description,
          'contactPerson': contactPerson,
          'phone': phone,
          'email': email,
          'logo': logo,
        }));

    return (data.body as Map<String, dynamic>)['status'] as String;
  }

  /// Get the registration status of a company
  ///
  /// Returns the status of the registration or throws an error.
  ///
  /// If you need the Key ID, use [MonoCorpRequestKey.keyId] instead.
  Future<String> getRegistrationStatus({
    required String pubKey,
  }) async {
    final data = await call(APIRequest('personal/auth/registration/status',
        methodId: 'personal/auth/registration/status',
        useAuth: true,
        data: {
          'pubkey': pubKey,
        },
        headers: {
          'X-Sign': '',
        }));

    return (data.body as Map<String, dynamic>)['status'] as String;
  }

  /// Get company data
  Future<MonoCorpCompanyData> getCompany() async {
    final data = await call(APIRequest('personal/corp/settings',
        methodId: 'personal/corp/settings',
        useAuth: true,
        data: {},
        headers: {
          'X-Sign': '',
        }));

    return MonoCorpCompanyData.fromJson(data.body as Map<String, dynamic>);
  }

  /// Set the webhook URL for statement events and other notifications
  ///
  /// A test request will be sent to the webhook URL to check its validity. The
  /// server must respond with a 200 status code.
  Future<void> setWebhook(Uri? webHookUrl) async {
    await call(APIRequest(
      'personal/corp/webhook',
      methodId: 'personal/corp/webhook',
      useAuth: true,
      data: {
        'webHookUrl': webHookUrl != null ? webHookUrl.toString() : '',
      },
      headers: {
        'X-Sign': '',
      },
    ));
  }

  /// Request access to the user's data
  ///
  /// [callback] - Webhook URL where Monobank will send the user's token
  /// in X-Request-Id header
  Future<MonoDataAccessRequest> requestAccess(Uri callback) async {
    final data = await call(APIRequest('personal/auth/request',
        methodId: 'personal/auth/request',
        useAuth: true,
        data: {},
        headers: {
          'X-Sign': '',
          'X-Callback': callback.toString(),
        }));

    return MonoDataAccessRequest.fromJson(data.body as Map<String, dynamic>);
  }
}

/// Mono Corp API methods for personal data
///
/// See [MonoCorpAPIUser] for use.
mixin CorpUserMethods on API {
  /// Check if the token is valid
  ///
  /// Returns true if the token is valid, throws an error otherwise.
  Future<bool> checkToken() async {
    await call(APIRequest(
      'personal/auth/request',
      methodId: 'personal/auth/request',
      useAuth: true,
      data: {},
    ));

    return true;
  }
}

/// Mono Corp API
///
/// This class is used to interact with the Mono Corp API without access to
/// personal data. It's used to control the company registered in Mono Corp API
/// and to request access to the user's data.
///
/// Unlike [MonoAPI], this class is designed for server side requests and
/// API methods have next to no rate limits. This doesn't apply to exchange
/// rate APIs, which don't support authentication and are always rate limited.
///
/// Use [MonoCorpAPI.user] to create an instance of [MonoCorpAPIUser] to access
/// personal data.
///
/// Note that [APIFlags.waiting] is removed from the settings mask for all
/// requests, as it's undesirable to queue requests to cart in server side
/// applications.
class MonoCorpAPI extends API
    with CurrencyMethods, PersonalMethods, CorpControlMethods {
  /// Create a new instance of [MonoCorpAPI]
  ///
  /// [privateKey] - private key used to sign requests. See [MonoCorpRequestKey]
  /// [domain] - domain of the API
  /// [requestId] - not used
  MonoCorpAPI(this.privateKey,
      {String domain = 'https://api.monobank.ua/', String? requestId})
      : super(
          Uri.parse(domain),
          requestTimeouts: {
            'bank/currency': Duration(minutes: 1),
          },
          token: requestId,
        );

  /// Private key used to sign requests
  final MonoCorpRequestKey privateKey;

  @override
  Future<APIResponse> call(APIRequest request) {
    // If skipping features not used - do not queue requests to cart
    if (request.settings & (APIFlags.skip | APIFlags.skipGlobal) == 0) {
      // Remove waiting flag
      int newSettingsMask = request.settings;
      newSettingsMask &= ~APIFlags.waiting;
      request.settings = newSettingsMask;
    }

    return super.call(request);
  }

  @override
  void authAttacher(APIRequest request) {
    final requestId = request.headers['X-Sign'] ?? token;

    if (requestId == null) {
      throw ArgumentError(
          'Second sign ingredient is missing.\n\n When accessing personal data, '
          "it's usually X-Request-Id header, that you would define when "
          'creating MonoCorpAPIUser instance. In other methods, X-Sign header '
          'is expected to be populated with the second sign ingredient, '
          'that the library will use to generate a proper X-Sign header.');
    }

    final unixTime = DateTime.now().millisecondsSinceEpoch ~/ 1000;

    String path = request.method;
    if (!path.startsWith('/')) {
      path = '/$path';
    }

    final message = '$unixTime$requestId$path';

    request.headers['X-Time'] = unixTime.toString();
    request.headers['X-Key-Id'] = privateKey.keyId;
    request.headers['X-Sign'] = privateKey.sign(message);

    if (token != null) {
      request.headers['X-Request-Id'] = token!;
    }
  }

  /// Create a new instance of [MonoCorpAPIUser]
  ///
  /// [requestId] - X-Request-Id header
  MonoCorpAPIUser user({required String requestId}) {
    return MonoCorpAPIUser(
      privateKey,
      requestId: requestId,
      domain: domain.toString(),
    );
  }
}

/// Mono Corp API for personal data
///
/// This class is used to interact with the Mono Corp API with access to
/// personal data. It's used to request the user's data.
///
/// See [MonoCorpAPI] for more information.
class MonoCorpAPIUser extends MonoCorpAPI with CorpUserMethods {
  /// Create a new instance of [MonoCorpAPIUser]
  ///
  /// [privateKey] - private key used to sign requests. See [MonoCorpRequestKey]
  /// [requestId] - X-Request-Id header
  /// [domain] - domain of the API
  MonoCorpAPIUser(
    super.privateKey, {
    required String super.requestId,
    super.domain,
  });
}
