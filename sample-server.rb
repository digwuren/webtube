#! /usr/bin/ruby

# A sample WEBrick server using the Webtube API.  It listens on port 8888 and
# provides two services: [[/diag]], which logs all the events from
# [[Webtube#run]] and remains silent towards the client (although note that
# the Webtube library pongs the pings), and [[/echo]], which echos.

require 'webrick'
require 'webtube/webrick'

class << diagnostic_listener = Object.new
  def respond_to? name
    return (name.to_s =~ /^on/ or super)
  end

  def method_missing name, *args
    output = "- #{name}("
    args.each_with_index do |arg, i|
      output << ', ' unless i.zero?
      if i.zero? and arg.is_a? Webtube then
        output << arg.to_s
      else
        output << arg.inspect
      end
    end
    output << ")"
    puts output
    return
  end
end

class << echo_listener = Object.new
  def onmessage webtube, data, opcode
    webtube.send_message data, opcode
    return
  end
end

server = WEBrick::HTTPServer.new(:Port => 8888)
server.mount_webtube '/diag', diagnostic_listener
server.mount_webtube '/echo', echo_listener

begin
  server.start
ensure
  server.shutdown
end
