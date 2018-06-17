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

NS_ASSUME_NONNULL_BEGIN

/// Flag for indicating the reason authorisation failed.
typedef NS_ENUM(NSInteger, JSMOAuth2Error) {
	//! Some other error (outside of the OAuth2 specification)
	JSMOAuth2ErrorUnknown,
	//! The client is not authorized to request an access token using this method.
	JSMOAuth2ErrorUnauthorizedClient,
	//! The resource owner or authorization server denied the request.
	JSMOAuth2ErrorAccessDenied,
	//! The authorization server does not support obtaining an access token using this method.
	JSMOAuth2ErrorUnsupportedResponseType,
	//! The requested scope is invalid, unknown, or malformed.
	JSMOAuth2ErrorInvalidScope,
	//! The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
	JSMOAuth2ErrorServerError,
	//! The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
	JSMOAuth2ErrorTemporarilyUnavailable,
};

/// Flag for indicating the level of success in migrating access tokens.
typedef NS_ENUM(NSInteger, JDBMigrationSuccess) {
	//! Tokens could not be migrated
	JDBMigrationFailed NS_SWIFT_NAME(failed),
	//! Some tokens could not be migrated
	JDBMigrationPartial NS_SWIFT_NAME(partial),
	//! All tokens migrated successfully
	JDBMigrationSuccessful NS_SWIFT_NAME(successful),
};

@class JDBAuthManager;

@protocol JDBAuthManagerDelegate

/// Called when the auth manager adds a new access token.
/// @param authManager The auth manager.
/// @param accessToken The access token that was added.
- (void)authManager:(JDBAuthManager *)authManager didAddAccessToken:(JDBAccessToken *)accessToken NS_SWIFT_NAME(authManager(_:didAdd:));

/// Called when the auth manager removes an access token.
/// @param authManager The auth manager.
/// @param accessToken The access token that was removed.
- (void)authManager:(JDBAuthManager *)authManager didRemoveAccessToken:(JDBAccessToken *)accessToken NS_SWIFT_NAME(authManager(_:didRemove:));

@end

@protocol JDBAuthManagerMigrationDelegate

/// Called when the auth manager detects access tokens to be migrated.
/// @param authManager The auth manager.
- (void)authManagerWillMigrateAccessTokens:(JDBAuthManager *)authManager NS_SWIFT_NAME(authManagerWillMigrateAccessTokens(_:));

/// Called when the auth manager completes migration of access tokens.
/// @param authManager The auth manager.
/// @param success Flag to indicate if access tokens were migrated successfully.
- (void)authManager:(JDBAuthManager *)authManager didMigrateAccessTokens:(JDBMigrationSuccess)success NS_SWIFT_NAME(authManagerDidMigrateAccessTokens(_:success:));

@end

@interface JDBAuthManager : NSObject

/// Delegate which gets notified when changes occur.
@property (nonatomic, weak, nullable) id<JDBAuthManagerDelegate> delegate;

/// Delegate which gets notified when migration starts and finishes.
@property (nonatomic, weak, nullable) id<JDBAuthManagerMigrationDelegate> migrationDelegate;

/// The application's consumer key.
/// Found in the Dropbox developer console: <https://www.dropbox.com/developers/apps>
@property (nonatomic, copy, readonly) NSString *appKey;

/// The application's consumer secret.
/// This is only used for migration of OAuth 1.0 access tokens, and can be `nil` (which will prevent migration).
@property (nonatomic, copy, readonly, nullable) NSString *appSecret;

// @name Instance

/// Create an auth manager with the given app key.
/// @param appKey The app key to use for authorisation (optional).
/// @param appSecret The app secret to use for migrating OAuth 1.0 access tokens.
- (instancetype)initWithAppKey:(NSString *)appKey andSecret:(NSString * _Nullable)appSecret NS_SWIFT_NAME(init(key:secret:));

/// Create an auth manager with the given app key.
/// @param appKey The app key to use for authorisation.
- (instancetype)initWithAppKey:(NSString *)appKey NS_SWIFT_NAME(init(key:));

// @name Handling authorisation

/// Opens the Dropbox app (if possible) with the OAuth2 authorization request.
/// @return Flag to indicate if the app could be opened or not. If false, fall back to presenting the `authViewController`, or using `authorizeInSafari`.
- (BOOL)authorizeWithDropboxApp NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.");

/// Opens the Dropbox website (if possible) with the OAuth2 authorization request.
/// @return Flag to indicate if the link could be opened or not. If false, fall back to presenting the `authViewController`.
- (BOOL)authorizeInSafari NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.");

/// View controller for presenting the OAuth2 authorization request page.
@property (nonatomic, strong, readonly) __kindof UIViewController *authViewController NS_CLASS_AVAILABLE_IOS(9_0);

/// Present the OAuth2 authorization request page by presenting a web view controller modally.
/// This is the equivalent of the Dropbox SDK's method of the same name.
/// @param controller The controller to present from.
- (void)authorizeFromController:(UIViewController *)controller NS_SWIFT_NAME(authorize(from:)) NS_EXTENSION_UNAVAILABLE_IOS("Use the `authViewController` where appropriate instead.");

/// Try to handle a redirect back into the application
/// @param url The URL to attempt to handle.
/// @return `nil` if SwiftyDropbox cannot handle the redirect URL, otherwise returns the `DropboxAuthResult`.
- (JDBAccessToken * _Nullable)handleRedirectURL:(NSURL *)url error:(NSError **)error NS_SWIFT_NAME(handle(_:));

// @name Handling access tokens

/// Check if there are any stored access tokens
/// @return Whether there are stored access tokens
@property (nonatomic, readonly) BOOL hasAccessTokens;

/// Retrieve all stored access tokens
/// @return An array of all stored access tokens
@property (nonatomic, strong, readonly) NSArray<JDBAccessToken *> *accessTokens;

/// Utility function to return an arbitrary access token
/// @return the "first" access token found, if any (otherwise `nil`)
@property (nonatomic, strong, readonly, nullable) JDBAccessToken *firstAccessToken;

/// Retrieve the access token for a particular user identifier
/// @param uid The user whose token to retrieve
/// @return An access token if present, otherwise `nil`.
- (JDBAccessToken * _Nullable)accessTokenForUserID:(NSString *)uid NS_SWIFT_NAME(accessToken(for:));

/// Delete a specific access token
/// @param token The access token to delete
/// @return whether the operation succeeded
- (BOOL)removeAccessToken:(JDBAccessToken *)token NS_SWIFT_NAME(remove(_:));

/// Delete all stored access tokens
/// @return whether the operation succeeded
- (BOOL)removeAllAccessTokens;

@end

NS_ASSUME_NONNULL_END
