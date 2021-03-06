Gem::Specification.new do |s|
  s.name = 'webtube'
  s.version = '1.1.0'
  s.date = '2018-04-26'
  s.homepage = 'https://github.com/digwuren/webtube'
  s.summary = 'A Ruby implementation of the WebSocket protocol'
  s.author = 'Andres Soolo'
  s.email = 'dig@mirky.net'
  s.files = File.read('Manifest.txt').split(/\n/)
  s.executables << 'wsc'
  s.license = 'GPL-3.0'
  s.description = <<EOD
Webtube is an implementation of the WebSocket protocol for Ruby.
Some integration with the WEBrick server is also included.
EOD
  s.has_rdoc = false
end
