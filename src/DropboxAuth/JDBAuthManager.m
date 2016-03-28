//
// Copyright © 2016 Daniel Farrelly
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
#import <DropboxAuth/JDBAuthManager.h>
#import <DropboxAuth/JDBKeychainManager.h>

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

@end

@implementation JDBAuthManager

#pragma mark - Instance

- (instancetype)initWithAppKey:(NSString *)appKey host:(NSString *)host {
    if( ( self = [super init] ) ) {
        _appKey = appKey;
        _host = host;
        _redirectURL = [NSURL URLWithString:[NSString stringWithFormat:@"db-%@://2/token",appKey]];
        _dauthRedirectURL = [NSURL URLWithString:[NSString stringWithFormat:@"db-%@://1/connect",appKey]];
    }
    return self;
}

- (instancetype)initWithAppKey:(NSString *)appKey {
    return [self initWithAppKey:appKey host:@"www.dropbox.com"];
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
    components.host = self.host;
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
	if( ! [self authorizeWithDropboxApp] ) {
		[controller presentViewController:self.authViewController animated:YES completion:nil];
	}
}

- (BOOL)authorizeWithDropboxApp {
	if( ! [self conformsToAppScheme] ) {
		NSLog(@"DropboxSDK: unable to link; app isn't registered for correct URL scheme (db-%@)",self.appKey);
		return NO;
	}

	if( ! [self hasApplicationQueriesScheme] ) {
		NSLog(@"DropboxSDK: unable to link; app isn't registered to query for URL scheme dbapi-2. Add a dbapi-2 entry to LSApplicationQueriesSchemes");
		return NO;
	}

	if( [[UIApplication sharedApplication] canOpenURL:[self dAuthURL:nil]]) {
		return NO;
	}

	NSString *nonce = [[NSUUID UUID] UUIDString];
	[[NSUserDefaults standardUserDefaults] setObject:nonce forKey:kDBLinkNonce];
	[[NSUserDefaults standardUserDefaults] synchronize];
	return [[UIApplication sharedApplication] openURL:[self dAuthURL:nonce]];
}

- (UIViewController *)authViewController {
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

	JDBAccessToken *result;
	if( [url.host isEqualToString:@"1"] ) {
		result = [self extractfromDAuthURL:url error:error];
	} else {
		result = [self extractFromRedirectURL:url error:error];
	}

	if( result != nil && ! [JDBKeychainManager setValue:result.accessToken forKey:result.uid] ) {
		NSDictionary *userInfo = @{ NSLocalizedDescriptionKey: @"Writing the access token to Keychain failed." };
		if( error != NULL ) *error = [NSError errorWithDomain:@"JSMKeychainManagerError" code:0 userInfo:userInfo];
		result = nil;
	}

	if( self.safariViewController != nil && self.safariViewController.presentingViewController != nil ) {
		[self safariViewControllerDidFinish:self.safariViewController];
	}

	return result;
}

#pragma mark - Handling access tokens

- (NSDictionary<NSString *,JDBAccessToken *> *)accessTokens {
	NSArray *users = [JDBKeychainManager getAll];
	NSMutableDictionary *ret = [NSMutableDictionary dictionary];
	for( NSString *user in users ) {
		NSString *accessToken = [JDBKeychainManager valueForKey:user];
		if( accessToken != nil ) {
			ret[user] = [[JDBAccessToken alloc] initWithAccessToken:accessToken uid:user];
		}
	}
	return [ret copy];
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

	if( success && self.delegate && [self.delegate respondsToSelector:@selector(authManager:didAddAccessToken:)] ) {
		[self.delegate authManager:self didAddAccessToken:token];
	}

	return success;
}

- (BOOL)removeAccessToken:(JDBAccessToken *)token {
	BOOL success = [JDBKeychainManager removeValueForKey:token.uid];

	if( success && self.delegate && [self.delegate respondsToSelector:@selector(authManager:didRemoveAccessToken:)] ) {
		[self.delegate authManager:self didRemoveAccessToken:token];
	}
	
	return success;
}

- (BOOL)removeAllAccessTokens {
	NSArray *accessTokens = self.accessTokens.allValues;

	BOOL success = [JDBKeychainManager clearAll];

	for( JDBAccessToken *token in accessTokens ) {
		if( [self.accessTokens.allValues containsObject:token] ) continue;
		if( self.delegate && [self.delegate respondsToSelector:@selector(authManager:didRemoveAccessToken:)] ) {
			[self.delegate authManager:self didRemoveAccessToken:token];
		}
	}

	return success;
}

#pragma mark - Safari view controller delegate

- (void)safariViewController:(SFSafariViewController *)controller didCompleteInitialLoad:(BOOL)didLoadSuccessfully {
	_safariViewController = controller;
}

- (void)safariViewControllerDidFinish:(SFSafariViewController *)controller {
	[self.safariViewController dismissViewControllerAnimated:YES completion:^{
		_safariViewController = nil;
	}];
}

@end
