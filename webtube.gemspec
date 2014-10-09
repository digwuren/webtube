Gem::Specification.new do |s|
  s.name = 'webtube'
  s.version = '0.1.0'
  s.date = '2014-10-09'
  s.homepage = 'https://github.com/digwuren/webtube'
  s.summary = 'A Ruby implementation of the [[WebSocket]] protocol'
  s.author = 'Andres Soolo'
  s.email = 'dig@mirky.net'
  s.files = File.read('Manifest.txt').split(/\n/)
  s.license = 'GPL-3'
  s.description = <<EOD
Webtube is an implementation of the [[WebSocket]] protocol for [[Ruby]].  Some
integration with the [[WEBrick]] server is also included.
EOD
  s.has_rdoc = false
end
