Pod::Spec.new do |spec|
  spec.name         = 'SharedAES-GCM'
  spec.version      = '1.0.0'
  spec.license      = { :type => 'Public Domain' }
  spec.homepage     = 'https://github.com/mukarev/SharedAES-GCM'
  spec.authors      = { 'Markus Kosmal' => 'mukarev@gmail.com'}
  spec.summary      = 'AES-GCM based on C reference'
  
  spec.description  =  <<-DESC
    Wrapper for AES-GCM.
  DESC

  spec.source       = { :git => 'https://github.com/mukarev/SharedAES-GCM.git', :tag => "#{spec.version}" }
  spec.source_files = 'Sources/*.{h,c}', 'Classes/*.{h,m}'
  spec.public_header_files = 'Classes/*.h'
  spec.requires_arc = true
end
