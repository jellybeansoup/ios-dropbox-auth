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

@import Foundation;
@import UIKit;
#import <DropboxAuth/JDBAccessToken.h>

typedef NS_ENUM(NSInteger, JSMOAuth2Error) {
	/// Some other error (outside of the OAuth2 specification)
	JSMOAuth2ErrorUnknown,
	/// The client is not authorized to request an access token using this method.
	JSMOAuth2ErrorUnauthorizedClient,
	/// The resource owner or authorization server denied the request.
	JSMOAuth2ErrorAccessDenied,
	/// The authorization server does not support obtaining an access token using this method.
	JSMOAuth2ErrorUnsupportedResponseType,
	/// The requested scope is invalid, unknown, or malformed.
	JSMOAuth2ErrorInvalidScope,
	/// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
	JSMOAuth2ErrorServerError,
	/// The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	JSMOAuth2ErrorTemporarilyUnavailable,
};

typedef NS_ENUM(NSInteger, JDBMigrationSuccess) {
	//! Tokens could not be migrated
	JDBMigrationFailed,
	//! Some tokens could not be migrated
	JDBMigrationPartial,
	//! All tokens migrated successfully
	JDBMigrationSuccessful,
};

@class JDBAuthManager;

@protocol JDBAuthManagerDelegate <NSObject>
@optional

/// Called when the auth manager adds a new access token.
- (void)authManager:(JDBAuthManager *)authManager didAddAccessToken:(JDBAccessToken *)accessToken;

/// Called when the auth manager removes an access token.
- (void)authManager:(JDBAuthManager *)authManager didRemoveAccessToken:(JDBAccessToken *)accessToken;

- (void)authManager:(JDBAuthManager *)authManager didMigrateAccessTokens:(JDBMigrationSuccess)success;

@end

@interface JDBAuthManager : NSObject

@property (nonatomic, strong) id<JDBAuthManagerDelegate> delegate;

@property (nonatomic, strong, readonly) NSString *appKey;

@property (nonatomic, strong, readonly) NSString *appSecret;

@property (nonatomic, strong, readonly) NSString *host;

// @name Instance

/// Create an auth manager with the given app key and host name.
/// @param appKey The app key to use for authorisation.
/// @param host The host name to use when accessing Dropbox.
- (instancetype)initWithAppKey:(NSString *)appKey host:(NSString *)host;

/// Create an auth manager with the given app key.
/// @param appKey The app key to use for authorisation.
- (instancetype)initWithAppKey:(NSString *)appKey;

/// Create an auth manager with the given app key and host name.
/// @param appKey The app key to use for authorisation.
/// @param appSecret The app secret to use for authorisation (optional).
/// @param host The host name to use when accessing Dropbox.
- (instancetype)initWithAppKey:(NSString *)appKey andSecret:(NSString *)appSecret host:(NSString *)host;

/// Create an auth manager with the given app key.
/// @param appKey The app key to use for authorisation (optional).
/// @param appSecret The app secret to use for authorisation.
- (instancetype)initWithAppKey:(NSString *)appKey andSecret:(NSString *)appSecret;

// @name Handling authorisation

/// Opens the Dropbox app (if possible) with the OAuth2 authorization request.
/// @return Flag to indicate if the app could be opened or not. If false, fall back to presenting the `authViewController`.
- (BOOL)authorizeWithDropboxApp NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.");

/// View controller for presenting the OAuth2 authorization request page.
@property (nonatomic, strong, readonly) __kindof UIViewController *authViewController;

/// Present the OAuth2 authorization request page by presenting a web view controller modally.
/// This is the equivalent of the Dropbox SDK's method of the same name.
/// @param controller The controller to present from.
- (void)authorizeFromController:(UIViewController *)controller NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.");

/// Try to handle a redirect back into the application
/// @param url The URL to attempt to handle.
/// @return `nil` if SwiftyDropbox cannot handle the redirect URL, otherwise returns the `DropboxAuthResult`.
- (JDBAccessToken *)handleRedirectURL:(NSURL *)url error:(NSError **)error;

// @name Handling access tokens

/// Check if there are any stored access tokens
/// @return Whether there are stored access tokens
@property (nonatomic, readonly) BOOL hasAccessTokens;

/// Retrieve all stored access tokens
/// @return A dictionary mapping users to their access tokens
@property (nonatomic, strong, readonly) NSDictionary<NSString *,JDBAccessToken *> *accessTokens;

/// Utility function to return an arbitrary access token
/// @return the "first" access token found, if any (otherwise `nil`)
@property (nonatomic, strong, readonly) JDBAccessToken *firstAccessToken;

/// Retrieve the access token for a particular user identifier
/// @param uid The user whose token to retrieve
/// @return An access token if present, otherwise `nil`.
- (JDBAccessToken *)accessTokenForUserID:(NSString *)uid;

/// Save an access token
/// @param token The access token to save
/// @return whether the operation succeeded
- (BOOL)addAccessToken:(JDBAccessToken *)token;

/// Delete a specific access token
/// @param token The access token to delete
/// @return whether the operation succeeded
- (BOOL)removeAccessToken:(JDBAccessToken *)token;

/// Delete all stored access tokens
/// @return whether the operation succeeded
- (BOOL)removeAllAccessTokens;

@end
