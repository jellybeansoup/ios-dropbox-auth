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

@import DropboxAuth;
#import "ViewController.h"

@interface ViewController ()

@property (nonatomic, strong) IBOutlet UIButton *connectButton;

@property (nonatomic, strong) IBOutlet UIView *accountView;

@property (nonatomic, strong) IBOutlet UILabel *accountLabel;

@end

@implementation ViewController

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	JDBAuthManager *authManager = [(AppDelegate *)[[UIApplication sharedApplication] delegate] dropboxAuthManager];
	JDBAccessToken *accessToken = authManager.firstAccessToken;
	if( accessToken != nil ) {
		self.connectButton.hidden = YES;
		self.accountView.hidden = NO;
		self.accountLabel.text = @"Loading account details…";

		NSURL *url = [NSURL URLWithString:@"https://api.dropboxapi.com/2/users/get_current_account"];
		NSMutableURLRequest *request = [[accessToken signedRequestWithURL:url] mutableCopy];
		request.HTTPMethod = @"POST";

		NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {

			dispatch_async(dispatch_get_main_queue(), ^{
				NSData *convertedData = [NSData dataWithBytes:data.bytes length:data.length];
				id responseObject = [NSJSONSerialization JSONObjectWithData:convertedData options:0 error:nil];
				if( responseObject != nil && [responseObject isKindOfClass:[NSDictionary class]] ) {
					NSDictionary *responseDictionary = (NSDictionary *)responseObject;
					self.accountLabel.text = responseDictionary[@"email"];
				}
				else if( responseObject == nil ) {
					self.accountLabel.text = [[NSString alloc] initWithData:convertedData encoding:NSUTF8StringEncoding];
				}
				else {
					self.accountLabel.text = @"Failed for unknown reasons.";
				}
			});

		}];

		[task resume];
	}

	else {
		self.connectButton.hidden = NO;
		self.accountView.hidden = YES;
	}
}

- (IBAction)connect:(id)sender {
	JDBAuthManager *authManager = [(AppDelegate *)[[UIApplication sharedApplication] delegate] dropboxAuthManager];

	if( ! [authManager authorizeWithDropboxApp] ) {
		[self presentViewController:authManager.authViewController animated:YES completion:nil];
	}
}

- (IBAction)disconnect:(id)sender {
	JDBAuthManager *authManager = [(AppDelegate *)[[UIApplication sharedApplication] delegate] dropboxAuthManager];
	[authManager removeAllAccessTokens];

	if( authManager.firstAccessToken == nil ) {
		self.connectButton.hidden = NO;
		self.accountView.hidden = YES;
	}

	else {

	}
}

@end
