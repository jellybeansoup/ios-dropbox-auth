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

#import "JDBAccessToken.h"

@implementation JDBAccessToken

- (instancetype)initWithAccessToken:(NSString *)accessToken uid:(NSString *)uid {
	if( ( self = [super init] ) ) {
		_accessToken = accessToken;
		_uid = uid;
	}
	return self;
}

- (NSString *)description {
	return [NSString stringWithFormat:@"<%@ uid:%@ accessToken:%@>", NSStringFromClass(self.class), self.uid, self.accessToken];
}

- (NSURLRequest *)signedRequestFromRequest:(NSURLRequest *)request {
	NSMutableURLRequest *mutableRequest = [request mutableCopy];
	NSString *authorization = [NSString stringWithFormat:@"Bearer %@",self.accessToken];
	[mutableRequest addValue:authorization forHTTPHeaderField:@"Authorization"];
	return [mutableRequest copy];
}

- (NSURLRequest *)signedRequestWithURL:(NSURL *)url cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
	NSURLRequest *request = [NSURLRequest requestWithURL:url cachePolicy:cachePolicy timeoutInterval:timeoutInterval];
	return [self signedRequestFromRequest:request];
}

- (NSURLRequest *)signedRequestWithURL:(NSURL *)url {
	NSURLRequest *request = [NSURLRequest requestWithURL:url];
	return [self signedRequestFromRequest:request];
}

@end
