//
// Copyright © 2019 Daniel Farrelly
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// *	Redistributions of source code must retain the above copyright notice, this list
//		of conditions and the following disclaimer.
// *	Redistributions in binary form must reproduce the above copyright notice, this
//		list of conditions and the following disclaimer in the documentation and/or
//		other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

@import SafariServices;
@import AuthenticationServices;
#import <CommonCrypto/CommonHMAC.h>
#import "JDBAuthManager.h"
#import "JDBKeychainManager.h"

NSString *const kDBLinkNonce = @"dropbox.sync.nonce";

static JSMOAuth2Error JSMOAuth2ErrorFromString(NSString *errorCode) {
	if( errorCode == nil ) {
		return JSMOAuth2ErrorUnknown;
	}
	else if( [errorCode isEqualToString:@"unauthorized_client"] ) {
		return JSMOAuth2ErrorUnauthorizedClient;
	}
	else if( [errorCode isEqualToString:@"access_denied"] ) {
		return JSMOAuth2ErrorAccessDenied;
	}
	else if( [errorCode isEqualToString:@"unsupported_response_type"] ) {
		return JSMOAuth2ErrorUnsupportedResponseType;
	}
	else if( [errorCode isEqualToString:@"invalid_scope"] ) {
		return JSMOAuth2ErrorInvalidScope;
	}
	else if( [errorCode isEqualToString:@"server_error"] ) {
		return JSMOAuth2ErrorServerError;
	}
	else if( [errorCode isEqualToString:@"temporarily_unavailable"] ) {
		return JSMOAuth2ErrorTemporarilyUnavailable;
	}
	return JSMOAuth2ErrorUnknown;
}

@interface JDBAuthManager () <SFSafariViewControllerDelegate>

@property (nonatomic, strong, readonly) NSURL *redirectURL;

@property (nonatomic, strong, readonly) NSURL *dauthRedirectURL;

@property (nonatomic, strong, readonly) SFSafariViewController *safariViewController;

@property (nonatomic, strong, readonly) SFAuthenticationSession *sfAuthenticationSession API_DEPRECATED_WITH_REPLACEMENT("-asWebAuthenticationSession", ios(11.0, 12.0));

@property (nonatomic, strong, readonly) ASWebAuthenticationSession *asWebAuthenticationSession API_AVAILABLE(ios(12.0));

@end

@implementation JDBAuthManager

#pragma mark - Instance

- (instancetype)initWithAppKey:(NSString *)appKey andSecret:(NSString *)appSecret {
	if( ( self = [super init] ) ) {
		_appKey = appKey;
		_appSecret = appSecret;
		_redirectURL = [NSURL URLWithString:[NSString stringWithFormat:@"db-%@://2/token",appKey]];
		_dauthRedirectURL = [NSURL URLWithString:[NSString stringWithFormat:@"db-%@://1/connect",appKey]];

		[self _performMigration];
	}
	return self;
}

- (instancetype)initWithAppKey:(NSString *)appKey {
	return [self initWithAppKey:appKey andSecret:nil];
}

#pragma mark - Handling authorisation

- (BOOL)conformsToAppScheme {
    NSString *appScheme = [NSString stringWithFormat:@"db-%@",self.appKey];

    id urlTypes = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
    if( urlTypes == nil || ! [urlTypes isKindOfClass:[NSArray class]] ) { return NO; }

    for( NSDictionary *urlType in (NSArray *)urlTypes ) {

        id schemes = urlType[@"CFBundleURLSchemes"];
        if( schemes == nil || ! [schemes isKindOfClass:[NSArray class]] ) { continue; }

        for( NSString *scheme in (NSArray *)schemes ) {
            if( [scheme isEqualToString:appScheme] ) {
                return YES;
            }
        }

    }
    
    return NO;
}

- (BOOL)hasApplicationQueriesScheme {
    id queriesSchemes = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"LSApplicationQueriesSchemes"];
    if( queriesSchemes == nil || ! [queriesSchemes isKindOfClass:[NSArray class]] ) { return NO; }

    for( NSString *scheme in (NSArray *)queriesSchemes ) {
        if( [scheme isEqualToString:@"dbapi-2"] ) {
            return YES;
        }
    }

    return NO;
}

- (NSURL *)authURL {
    NSURLComponents *components = [NSURLComponents new];
    components.scheme = @"https";
    components.host = @"www.dropbox.com";
    components.path = @"/1/oauth2/authorize";

    components.queryItems = @[
                              [NSURLQueryItem queryItemWithName:@"response_type" value:@"token"],
                              [NSURLQueryItem queryItemWithName:@"client_id" value: self.appKey],
                              [NSURLQueryItem queryItemWithName:@"redirect_uri" value: self.redirectURL.absoluteString],
                              [NSURLQueryItem queryItemWithName:@"disable_signup" value: @"true"],
                              ];

    return components.URL;
}

- (NSURL *)dAuthURL:(NSString *)nonce {
	NSURLComponents *components = [NSURLComponents new];
	components.scheme = @"dbapi-2";
	components.host = @"1";
	components.path = @"/connect";

	if( nonce != nil ) {
		NSString *state = [NSString stringWithFormat:@"oauth2:%@",nonce];
		components.queryItems = @[
								  [NSURLQueryItem queryItemWithName:@"k" value:self.appKey],
								  [NSURLQueryItem queryItemWithName:@"s" value: @""],
								  [NSURLQueryItem queryItemWithName:@"state" value: state],
								  ];
	}

	return components.URL;
}

- (BOOL)canHandleURL:(NSURL *)url {
    for( NSURL *known in @[self.redirectURL, self.dauthRedirectURL] ) {
        if (url.scheme == known.scheme &&  url.host == known.host && url.path == known.path) {
            return YES;
        }
    }

    return NO;
}

- (void)authorizeFromController:(UIViewController *)controller {
	[self authorizeFromController:controller completion:nil];
}

- (void)authorizeFromController:(UIViewController *)controller completion:(void(^ _Nullable)(JDBAccessToken *accessToken, NSError *error))completion {
	if( @available(iOS 12.0, *) ) {
		NSURL *url = [self authURL];
		NSString *scheme = [NSString stringWithFormat:@"db-%@", self.appKey];

		_asWebAuthenticationSession = [[ASWebAuthenticationSession alloc] initWithURL:url callbackURLScheme:scheme completionHandler:^(NSURL *callbackURL, NSError *error) {
			if( error != nil && completion != nil ) {
				completion(nil, error);
			}
			else if (error == nil) {
				NSError *tokenError;
				JDBAccessToken *accessToken = [self handleRedirectURL:callbackURL error:&tokenError];

				if( completion != nil ) {
					completion(accessToken, tokenError);
				}
			}
		}];

		if( @available(iOS 13.0, *) ) {
			if( [controller conformsToProtocol:@protocol(ASWebAuthenticationPresentationContextProviding)] ) {
				_asWebAuthenticationSession.presentationContextProvider = (id<ASWebAuthenticationPresentationContextProviding>)controller;
			}
		}

		if( [_asWebAuthenticationSession start] ) {
			return;
		}
	}
	else if( @available(iOS 11.0, *) ) {
		#pragma clang diagnostic push
		#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		NSURL *url = [self authURL];
		NSString *scheme = [NSString stringWithFormat:@"db-%@", self.appKey];

		_sfAuthenticationSession = [[SFAuthenticationSession alloc] initWithURL:url callbackURLScheme:scheme completionHandler:^(NSURL *callbackURL, NSError *error) {
			if( error != nil && completion != nil ) {
				completion(nil, error);
			}
			else if (error == nil) {
				NSError *tokenError;
				JDBAccessToken *accessToken = [self handleRedirectURL:callbackURL error:&tokenError];

				if( completion != nil ) {
					completion(accessToken, tokenError);
				}
			}
		}];

		if( [_sfAuthenticationSession start] ) {
			return;
		}
		#pragma clang diagnostic pop
	}

	if( [self authorizeWithDropboxApp] ) {
		return;
	}
	else if( NSClassFromString(@"SFSafariViewController") != nil ) {
		[controller presentViewController:self.authViewController animated:YES completion:nil];
	}
	else {
		[self authorizeInSafari];
	}

}

- (BOOL)authorizeWithDropboxApp NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.") {
	if( ! [self conformsToAppScheme] ) {
		NSLog(@"DropboxSDK: unable to link; app isn't registered for correct URL scheme (db-%@).",self.appKey);
		return NO;
	}

	NSString *nonce = [[NSUUID UUID] UUIDString];
	NSURL *url = [self dAuthURL:nonce];

	if( ! [[UIApplication sharedApplication] canOpenURL:url] ) {
		return NO;
	}

	[[NSUserDefaults standardUserDefaults] setObject:nonce forKey:kDBLinkNonce];
	[[NSUserDefaults standardUserDefaults] synchronize];

	if (@available(iOS 10.0, *)) {
		[[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];

		return YES;
	}
	else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		return [[UIApplication sharedApplication] openURL:url];
#pragma clang diagnostic pop
	}
}

- (BOOL)authorizeInSafari NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.") {
	if( ! [[UIApplication sharedApplication] canOpenURL:[self authURL]] ) {
		return NO;
	}

	if (@available(iOS 10.0, *)) {
		[[UIApplication sharedApplication] openURL:[self authURL] options:@{} completionHandler:nil];

		return YES;
	}
	else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		return [[UIApplication sharedApplication] openURL:[self authURL]];
#pragma clang diagnostic pop
	}
}

- (UIViewController *)authViewController NS_CLASS_AVAILABLE_IOS(9_0) {
	SFSafariViewController *safariViewController = [[SFSafariViewController alloc] initWithURL:[self authURL]];
	safariViewController.delegate = self;
	return (UIViewController *)safariViewController;
}

- (JDBAccessToken *)extractfromDAuthURL:(NSURL *)url error:(NSError **)error {
	NSString *path = url.path ?: @"";
	if( [path isEqualToString:@"/connect"] ) {
		NSMutableDictionary<NSString *,NSString *> *results = [NSMutableDictionary dictionary];
		NSArray *pairs = url.query != nil ? [url.query componentsSeparatedByString:@"&"] : @[];

		for( NSString *pair in pairs ) {
			NSArray *kv = [pair componentsSeparatedByString:@"="];
			[results setValue:kv[1] forKey:kv[0]];
		}
		NSArray *state = results[@"state"] != nil ? [results[@"state"] componentsSeparatedByString:@"%3A"] : @[];

		NSString *nonce = [[NSUserDefaults standardUserDefaults] objectForKey:kDBLinkNonce];
		if( state.count == 2 && [state[0] isEqualToString:@"oauth2"] && [state[1] isEqualToString:nonce] ) {
			NSString *accessToken = results[@"oauth_token_secret"];
			NSString *uid = results[@"uid"];
			return [[JDBAccessToken alloc] initWithAccessToken:accessToken uid:uid];
		}
		else {
			if( error != NULL ) *error = [NSError errorWithDomain:@"JSMOAuth2Error" code:JSMOAuth2ErrorUnknown userInfo:nil];
			return nil;
		}
	}

	else {
		if( error != NULL ) *error = [NSError errorWithDomain:@"JSMOAuth2Error" code:JSMOAuth2ErrorAccessDenied userInfo:nil];
		return nil;
	}
}

- (JDBAccessToken *)extractFromRedirectURL:(NSURL *)url error:(NSError **)error {
	NSMutableDictionary<NSString *,NSString *> *results = [NSMutableDictionary dictionary];
	NSArray *pairs = url.fragment != nil ? [url.fragment componentsSeparatedByString:@"&"] : @[];

	for( NSString *pair in pairs ) {
		NSArray *kv = [pair componentsSeparatedByString:@"="];
		[results setValue:kv[1] forKey:kv[0]];
	}

	if( results[@"error"] != nil ) {
		JSMOAuth2Error code = JSMOAuth2ErrorFromString(results[@"error"]);
		NSDictionary *userInfo = nil;
		if( results[@"error_description"] != nil ) {
			userInfo = @{ NSLocalizedDescriptionKey: [[results[@"error_description"] stringByReplacingOccurrencesOfString:@"+" withString:@" "] stringByRemovingPercentEncoding] };
		}
		if( error != NULL ) *error = [NSError errorWithDomain:@"JSMOAuth2Error" code:code userInfo:userInfo];
		return nil;
	}

	else {
		NSString *accessToken = results[@"access_token"];
		NSString *uid = results[@"uid"];
		return [[JDBAccessToken alloc] initWithAccessToken:accessToken uid:uid];
	}
}

- (JDBAccessToken *)handleRedirectURL:(NSURL *)url error:(NSError **)error {
	if( [self canHandleURL:url] ) {
		return nil;
	}

	JDBAccessToken *token;
	if( [url.host isEqualToString:@"1"] ) {
		token = [self extractfromDAuthURL:url error:error];
	} else {
		token = [self extractFromRedirectURL:url error:error];
	}

	if( token != nil && ! [self addAccessToken:token] ) {
		NSDictionary *userInfo = @{ NSLocalizedDescriptionKey: NSLocalizedString(@"Writing the access token to Keychain failed.",@"DROPBOXAUTH_WRITE_FAILURE") };
		if( error != NULL ) *error = [NSError errorWithDomain:@"JSMKeychainManagerError" code:0 userInfo:userInfo];
		token = nil;
	}

	if( NSClassFromString(@"SFSafariViewController") != nil && self.safariViewController != nil && self.safariViewController.presentingViewController != nil ) {
		[self safariViewControllerDidFinish:self.safariViewController];
	}

	return token;
}

#pragma mark - Handling access tokens

- (NSArray<JDBAccessToken *> *)accessTokens {
	NSArray *users = [JDBKeychainManager getAll];
	NSMutableArray *tokens = [NSMutableArray array];
	for( NSString *user in users ) {
		NSString *accessToken = [JDBKeychainManager valueForKey:user];
		if( accessToken == nil ) continue;
		[tokens addObject:[[JDBAccessToken alloc] initWithAccessToken:accessToken uid:user]];
	}
	return [tokens copy];
}

- (JDBAccessToken *)firstAccessToken {
	NSString *uid = [[JDBKeychainManager getAll] firstObject];
	return [self accessTokenForUserID:uid];
}

- (BOOL)hasAccessTokens {
	return [[self accessTokens] count] != 0;
}

- (JDBAccessToken *)accessTokenForUserID:(NSString *)uid {
	NSString *accessToken = [JDBKeychainManager valueForKey:uid];
	if( accessToken != nil ) {
		return [[JDBAccessToken alloc] initWithAccessToken:accessToken uid:uid];
	}

	else {
		return nil;
	}
}

- (BOOL)addAccessToken:(JDBAccessToken *)token {
	BOOL success = [JDBKeychainManager setValue:token.accessToken forKey:token.uid];

	if( success && self.delegate ) {
		[self.delegate authManager:self didAddAccessToken:token];
	}

	return success;
}

- (BOOL)removeAccessToken:(JDBAccessToken *)token {
	BOOL success = [JDBKeychainManager removeValueForKey:token.uid];

	if( success && self.delegate ) {
		[self.delegate authManager:self didRemoveAccessToken:token];
	}
	
	return success;
}

- (BOOL)removeAllAccessTokens {
	NSArray *accessTokens = self.accessTokens;

	BOOL success = [JDBKeychainManager clearAll];

	for( JDBAccessToken *token in accessTokens ) {
		if( [self accessTokenForUserID:token.uid] ) continue;
		if( self.delegate ) {
			[self.delegate authManager:self didRemoveAccessToken:token];
		}
	}

	return success;
}

#pragma mark - Safari view controller delegate

- (void)safariViewController:(SFSafariViewController *)controller didCompleteInitialLoad:(BOOL)didLoadSuccessfully NS_CLASS_AVAILABLE_IOS(9_0) {
	_safariViewController = controller;
}

- (void)safariViewControllerDidFinish:(SFSafariViewController *)controller NS_CLASS_AVAILABLE_IOS(9_0) {
	[self.safariViewController dismissViewControllerAnimated:YES completion:^{
		self->_safariViewController = nil;
	}];
}

#pragma mark - Migration

//! Migrate access tokens used by older SDKs to DropboxAuth's keychain.
- (void)_performMigration {
	if( self.appKey == nil || self.appSecret == nil ) return;

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		dispatch_async(dispatch_queue_create("com.jellystyle.DropboxAuth.migration", DISPATCH_QUEUE_SERIAL),^{

			NSMutableDictionary *credentials = [NSMutableDictionary dictionary];

			NSString *sdkID = [NSString stringWithFormat:@"%@.dropbox.auth", NSBundle.mainBundle.bundleIdentifier];
			NSDictionary *sdkCredentials = [self _credentialsForKeychainID:sdkID];
			if( sdkCredentials != nil && sdkCredentials[@"kDBDropboxUserCredentials"] != nil ) {
				for( NSDictionary *user in (NSArray *)sdkCredentials[@"kDBDropboxUserCredentials"] ) {
					NSString *uid = user[@"kDBDropboxUserId"];
					if( credentials[uid] != nil ) continue;
					[credentials setObject:@{ @"uid": uid, @"token": user[@"kMPOAuthCredentialAccessToken"], @"secret": user[@"kMPOAuthCredentialAccessTokenSecret"] } forKey:uid];
				}
			}

			NSString *syncID = [NSString stringWithFormat:@"%@.dropbox-sync.auth", NSBundle.mainBundle.bundleIdentifier];
			NSDictionary *syncCredentials = [self _credentialsForKeychainID:syncID];
			if( syncCredentials != nil && syncCredentials[@"accounts"] != nil && syncCredentials[@"accounts"][self.appKey] != nil ) {
				for( NSDictionary *user in (NSArray *)syncCredentials[@"accounts"][self.appKey] ) {
					NSString *uid = user[@"userId"];
					if( credentials[uid] != nil ) continue;
					[credentials setObject:@{ @"uid": uid, @"token": user[@"token"], @"secret": user[@"tokenSecret"] } forKey:uid];
				}
			}

			NSUInteger foundCredentials = credentials.count;

			if( foundCredentials > 0 && self.migrationDelegate ) {
				dispatch_async(dispatch_get_main_queue(),^{
					[self.migrationDelegate authManagerWillMigrateAccessTokens:self];
				});
			}

			for( NSDictionary *user in credentials.allValues ) {
				JDBAccessToken *token = [self _tokenForUser:user[@"uid"] withOAuth1Token:user[@"token"] andSecret:user[@"secret"]];

				if( token == nil ) continue;

				[self addAccessToken:token];
				[credentials removeObjectForKey:token.uid];
			}

			if( foundCredentials > 0 && self.migrationDelegate ) {
				JDBMigrationSuccess success = JDBMigrationFailed;
				if( credentials.count == 0 ) {
					success = JDBMigrationSuccessful;
				}
				else if( credentials.count < foundCredentials ) {
					success = JDBMigrationPartial;
				}
				dispatch_async(dispatch_get_main_queue(),^{
					[self.migrationDelegate authManager:self didMigrateAccessTokens:success];
				});
			}

		});
	});
}

//! Fetch stored credentials used by older Dropbox SDKs, using the given `keychainID`.
- (NSDictionary *)_credentialsForKeychainID:(NSString *)keychainID {
	NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
							(__bridge id)kSecAttrService: keychainID,
							(__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
							(__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
							(__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue};

	CFDictionaryRef result = NULL;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
	NSDictionary *attrDict = (__bridge_transfer NSDictionary *)result;
	NSData *foundValue = [attrDict objectForKey:(__bridge id)kSecValueData];

	if( status != noErr || foundValue == nil ) return nil;

	SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
											  (__bridge id)kSecAttrService: keychainID});

	if (@available(iOS 11.0, *)) {
		return [NSKeyedUnarchiver unarchivedObjectOfClass:[NSDictionary class] fromData:foundValue error:nil];
	}
	else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		return [NSKeyedUnarchiver unarchiveObjectWithData:foundValue];
#pragma clang diagnostic pop
	}
}

//! Get an OAuth2 token from Dropbox using a given OAuth1 token and token secret.
- (JDBAccessToken *)_tokenForUser:(NSString *)uid withOAuth1Token:(NSString *)token andSecret:(NSString *)secret {
	CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
	NSString *nonce = CFBridgingRelease(CFUUIDCreateString(kCFAllocatorDefault, uuid));
	CFRelease(uuid);

	NSURLComponents *components = [NSURLComponents componentsWithString:@"https://api.dropboxapi.com/1/oauth2/token_from_oauth1"];

	// Prepare our parameters as query items…
	NSMutableArray *queryItems = [NSMutableArray array];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_consumer_key" value:self.appKey]];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_nonce" value:nonce]];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_signature_method" value:@"HMAC-SHA1"]];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_timestamp" value:[NSString stringWithFormat:@"%d",(int)NSDate.date.timeIntervalSince1970]]];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_token" value:token]];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_version" value:@"1.0"]];

	// …sign the query…
	components.queryItems = queryItems;
	NSString *unsignedQuery = components.percentEncodedQuery;
	components.query = nil;

	NSMutableCharacterSet *unreservedCharacters = NSMutableCharacterSet.alphanumericCharacterSet;
	[unreservedCharacters addCharactersInString:@"-._~"];

	NSString *encodedURL = [components.string stringByAddingPercentEncodingWithAllowedCharacters:unreservedCharacters];
	NSString *encodedQuery = [unsignedQuery stringByAddingPercentEncodingWithAllowedCharacters:unreservedCharacters];
	NSData *baseData = [[NSString stringWithFormat:@"POST&%@&%@",encodedURL,encodedQuery] dataUsingEncoding:NSUTF8StringEncoding];

	NSString *encodedAppSecret = [self.appSecret stringByAddingPercentEncodingWithAllowedCharacters:unreservedCharacters];
	NSString *encodedSecret = [secret stringByAddingPercentEncodingWithAllowedCharacters:unreservedCharacters];
	NSData *secretData = [[NSString stringWithFormat:@"%@&%@", encodedAppSecret, encodedSecret] dataUsingEncoding:NSUTF8StringEncoding];

	NSMutableData *expectedData = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
	CCHmacContext hmac;
	CCHmacInit(&hmac, kCCHmacAlgSHA1, secretData.bytes, secretData.length);
	CCHmacUpdate(&hmac, baseData.bytes, baseData.length);
	CCHmacFinal(&hmac, expectedData.mutableBytes);

	NSString *signature = [expectedData base64EncodedStringWithOptions:0];
	[queryItems addObject:[NSURLQueryItem queryItemWithName:@"oauth_signature" value:signature]];

	// …then encode and remove them (for the POST body)
	components.queryItems = queryItems;
	NSString *signedQuery = components.percentEncodedQuery;
	components.query = nil;

	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:components.URL];
	request.allHTTPHeaderFields = @{ @"Content-Type": @"application/x-www-form-urlencoded", @"cache-control": @"no-cache" };
	request.HTTPMethod = @"POST";
	request.HTTPBody = [signedQuery dataUsingEncoding:NSUTF8StringEncoding];

	__block NSString *newToken = nil;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

	NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
		if( data == nil ) return;

		id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

		if( object != nil && ! [object isKindOfClass:[NSDictionary class]] ) return;

		NSDictionary *json = (NSDictionary *)object;

		if( json[@"access_token"] != nil && ! [json[@"access_token"] isKindOfClass:[NSString class]] ) return;

		newToken = (NSString *)json[@"access_token"];

		dispatch_semaphore_signal(semaphore);
	}];

	[task resume];

	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

	return newToken ? [[JDBAccessToken alloc] initWithAccessToken:newToken uid:uid] : nil;
}

@end
