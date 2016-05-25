Pod::Spec.new do |s|
  s.name         = "DropboxAuth"
  s.version      = "0.1.0"
  s.summary      = "A simple library for authorising Dropbox API requests on iOS."
  s.homepage     = "https://github.com/jellybeansoup/ios-dropbox-auth"
  s.license      = { :type => 'BSD', :file => 'LICENSE' }
  s.author       = { "Daniel Farrelly" => "daniel@jellystyle.com" }
  s.source       = { :git => "https://github.com/jellybeansoup/ios-dropbox-auth.git", :tag => "v0.1.0" }
  s.platform     = :ios, '8.4'
  s.requires_arc = true
  s.source_files = 'src/DropboxAuth/*.{h,m}'
  s.public_header_files = 'src/DropboxAuth/*.h'
end
