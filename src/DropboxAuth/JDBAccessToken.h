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

NS_ASSUME_NONNULL_BEGIN

@interface JDBAccessToken : NSObject

/// The access token string.
@property (nonatomic, strong, readonly) NSString *accessToken;

/// The associated user.
@property (nonatomic, strong, readonly) NSString *uid;

/// Create an instance of the receiver with the access token and uid.
- (instancetype)initWithAccessToken:(NSString *)accessToken uid:(NSString *)uid;

/// Create a URL request from the given request, signed using the receiver.
/// @param request The URL request to be signed.
/// @request The signed URL request.
- (NSURLRequest *)signedRequestFromRequest:(NSURLRequest *)request;

/// Create a URL request with the given URL, cache policy and timeout, signed using the receiver.
/// This method replicates the `requestWithURL:cachePolicy:timeoutInterval:` method on `NSURLRequest`, while also signing for access to the API.
/// @param url The URL for the new request.
/// @param cachePolicy The cache policy for the new request.
/// @param timeoutInterval The timeout interval for the new request, in seconds.
/// @request The signed URL request.
- (NSURLRequest *)signedRequestWithURL:(NSURL *)url cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval;

/// Create a URL request from the given URL, signed using the receiver.
/// This method replicates the `requestWithURL:` method on `NSURLRequest`, while also signing for access to the API.
/// @param url The URL for the new request.
/// @request The signed URL request.
- (NSURLRequest *)signedRequestWithURL:(NSURL *)url;

@end

NS_ASSUME_NONNULL_END
