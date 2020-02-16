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

@import Security;
#import "JDBKeychainManager.h"

@implementation JDBKeychainManager

+ (BOOL)setValue:(NSString *)value forKey:(NSString *)key {
	if( key == nil || value == nil ) return NO;

	NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];

	if( data == nil ) { return NO; }

	NSDictionary *query = [self jsm_queryWithDict:@{ (__bridge id)kSecAttrAccount: key, (__bridge id)kSecValueData: data }];

	[self jsm_delete:query];

	return [self jsm_add:query];
}

+ (NSString *)valueForKey:(NSString *)key {
	if( key == nil ) return nil;

	NSDictionary *query = [self jsm_queryWithDict:@{ (__bridge id)kSecAttrAccount: key,
													 (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
													 (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne }];

	CFDataRef dataResult = [self jsm_query:query];

	if( dataResult == nil ) { return nil; }

	return [[NSString alloc] initWithData:(__bridge NSData *)dataResult encoding:NSUTF8StringEncoding];
}

+ (BOOL)removeValueForKey:(NSString *)key {
	if( key == nil ) return NO;

	NSDictionary *query = [self jsm_queryWithDict:@{ (__bridge id)kSecAttrAccount: key }];

	return [self jsm_delete:query];
}

+ (NSArray<NSString *> *)getAll {
	NSDictionary *query = [self jsm_queryWithDict:@{ (__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
												 (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll }];

	CFArrayRef dataResult = [self jsm_query:query];

	if( dataResult == nil ) { return @[]; }

	NSArray *results = (__bridge NSArray *)dataResult;

	if( ! [results isKindOfClass:[NSArray class]] ) { return @[]; }

	NSMutableArray *mappedResults = [NSMutableArray array];
	[results enumerateObjectsUsingBlock:^(NSDictionary * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
		mappedResults[idx] = obj[@"acct"];
	}];
	return [mappedResults copy];
}

+ (BOOL)clearAll {
	NSDictionary *query = [self jsm_queryWithDict:@{}];

	return [self jsm_delete:query];
}

#pragma mark - Keychain wrappers

// These wrappers hit the keychain twice to avoid inaccurate errors.
// https://forums.developer.apple.com/thread/4743

+ (CFTypeRef)jsm_query:(NSDictionary *)query {
	CFDictionaryRef queryRef = (__bridge CFDictionaryRef)query;

	CFTypeRef dataResult = NULL;
	OSStatus status = SecItemCopyMatching(queryRef, &dataResult);

	if( status != noErr ) {
		status = SecItemCopyMatching(queryRef, &dataResult);
	}

	if( status != noErr ) {
		return nil;
	}

	return dataResult;
}

+ (BOOL)jsm_delete:(NSDictionary *)query {
	CFDictionaryRef queryRef = (__bridge CFDictionaryRef)query;

	OSStatus status = SecItemDelete(queryRef);

	if( status != noErr ) {
		status = SecItemDelete(queryRef);
	}

	return status == noErr;
}

+ (BOOL)jsm_add:(NSDictionary *)query {
	CFDictionaryRef queryRef = (__bridge CFDictionaryRef)query;

	OSStatus status = SecItemAdd(queryRef, nil);

	if( status != noErr ) {
		status = SecItemAdd(queryRef, nil);
	}

	return status == noErr;
}

#pragma mark - Utilities

+ (NSDictionary *)jsm_queryWithDict:(NSDictionary<NSString *, id> *)query {
    NSBundle *bundle = [NSBundle mainBundle];
    if( bundle.bundleURL.pathExtension != nil && [bundle.bundleURL.pathExtension isEqualToString:@"appex"] ) {
        // Peel off two directory levels - MY_APP.app/PlugIns/MY_APP_EXTENSION.appex
        // <http://stackoverflow.com/questions/26189060/get-the-main-app-bundle-from-within-extension>
        bundle = [NSBundle bundleWithURL:[[bundle.bundleURL URLByDeletingLastPathComponent] URLByDeletingLastPathComponent]];
    }
    
    NSString *bundleId = [bundle bundleIdentifier] ?: @"";
    NSMutableDictionary *queryDict = [query mutableCopy];

	queryDict[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
	queryDict[(__bridge id)kSecAttrService] = [NSString stringWithFormat:@"%@.dropbox.authv2",bundleId];

	return queryDict;
}

+ (void)jsm_listAllItems {
	NSDictionary *query = [self jsm_queryWithDict:@{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
												 (__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
												 (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll }];

	CFArrayRef dataResult = NULL;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&dataResult);

	if( status != noErr ) { return; }
	
	NSArray *results = (__bridge NSArray *)dataResult;
	if( ! [results isKindOfClass:[NSArray class]] ) {
		results = @[];
	}
	NSMutableArray *mappedResults = [NSMutableArray array];
	[results enumerateObjectsUsingBlock:^(NSDictionary * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
		mappedResults[idx] = @[obj[@"svce"],obj[@"acct"]];
	}];
	NSLog(@"dbgListAllItems: %@",mappedResults);
}

@end
