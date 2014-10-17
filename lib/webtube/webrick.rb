# webtube/webrick.rb -- WEBrick integration for Webtube, an implementation of
# the WebSocket protocol

require 'webrick'
require 'webrick/httprequest'
require 'webrick/httpserver'
require 'webrick/httpservlet'
require 'webrick/httpservlet/abstract'
require 'webtube'
require 'webtube/vital-statistics'

module WEBrick
  class HTTPRequest
    def websocket_upgrade_request?
      return self.request_method.upcase == 'GET' &&
          self.http_version >= '1.1' &&
          (self['Connection'] || '').downcase == 'upgrade' &&
          (self['Upgrade'] || '').downcase == 'websocket' &&
          !self['Sec-WebSocket-Key'].nil?
    end
  end

  class HTTPServer
    # Attach a [[Webtube::Vital_Statistics]] to new [[WEBrick::HTTPServer]]
    # instances so that the live webtubes could be closed upon shutdown

    alias orig_initialize_before_webtube_integration initialize
    def initialize config = {}, default = Config::HTTP
      orig_initialize_before_webtube_integration config, default
      @webtubes = Webtube::Vital_Statistics.new @logger
      return
    end

    def webtubes
      result = @webtubes
      # Usually, this should be it.
      if result.nil? then # ... but ...
        # Well, it would seem that our extended constructor was not called.
        # How could this have happened?
        result = @webtubes = Webtube::Vital_Statistics.new
        @logger.warn "@webtubes has not been set up before accessing it.  I " +
            "have attempted to correct this ex post facto, but doing it now " +
            "is a race condition, and I may have lost track of some webtubes " +
            "as a result.  The next time, please load webtube/webrick.rb " +
            "/before/ instantiating your WEBrick::Server."
      end
      return result
    end

    alias orig_shutdown_before_webtube_integration shutdown
    def shutdown
      # We'll need to call the original shutdown code first, for we want to
      # stop accepting new Webtube connections before 'close all Webtube
      # connections' will have a proper, thread-safe meaning.
      orig_shutdown_before_webtube_integration
      webtubes.close_all
      webtubes.thread_group.list.each &:join
      return
    end

    # Given a [[request]] and a [[response]] object, as prepared by a
    # [[WEBrick::HTTPServer]] for processing in a portlet, attempt to accept
    # the client's request to establish a WebSocket connection.  The
    # [[request]] must actually contain such a request; see
    # [[websocket_upgrade_request?]].
    #
    # The attempt will fail in the theoretical case the client and the server
    # can't agree on the protocol version to use.  In such a case,
    # [[accept_webtube]] will prepare a 426 'Upgrade required' response,
    # explaining in plain text what the problem is and advertising, using the
    # [[Sec-WebSocket-Version]] header field, the protocol version
    # (specifically, 13) it is prepared to speak.  When this happens, the
    # WebSocket session will never be set up and no [[listener]] events will be
    # called.
    #
    # Note that [[accept_webtube]] will manipulate [[response]] and return
    # immediately.  The actual WebSocket session will begin once WEBrick
    # attempts to deliver the [[response]], and will be marked by the newly
    # constructed [[Webtube]] instance delivering an [[onopen]] event to
    # [[listener]].
    #
    # Also note that the loop to process incoming WebSocket frames will hog the
    # whole thread; in order to deliver asynchronous messages over the
    # WebSocket, [[Webtube#send_message]] needs to be called from another
    # thread.  (For synchronous messages, it can safely be called from the
    # handlers inside [[listener]].)
    #
    # See [[Webtube#run]] for a list of the supported methods for the
    # [[listener]].
    def accept_webtube request, response, listener,
        session: nil, context: nil
      # Check that the client speaks our version
      unless (request['Sec-WebSocket-Version'] || '').split(/\s*,\s*/).
          include? '13' then
        @logger.error "Sec-WebSocket-Version mismatch"
        response.status, response.reason_phrase = '426', 'Upgrade required'
        response['Content-type'] = 'text/plain'
        response['Sec-WebSocket-Version'] = '13'
            # advertise the version we speak
        response.body = "This WebSocket server only speaks version 13 of the " +
            "protocol, as specified by RFC 6455.\n"
      else
        response.status, response.reason_phrase = '101', 'Hello WebSocket'
        response['Upgrade'] = 'websocket'
        response['Sec-WebSocket-Accept'] = Digest::SHA1.base64digest(
            request['Sec-WebSocket-Key'] +
            '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        response['Sec-WebSocket-Version'] = '13'
        response.keep_alive = false
            # so that WEBrick will close the TCP socket when we're done
        vital_statistics = self.webtubes
        (class << response; self; end).instance_eval do
          # We'll need to deliver the [[Connection: Upgrade]] header;
          # unfortunately, HTTPResponse#setup_header would munge it if we set
          # this header field in the ordinary way.  Accordingly, we'll have to
          # override the method.
          define_method :setup_header do ||
            super()
            @header['connection'] = 'Upgrade'
            return
          end

          # Replace [[response.send_body]] with the WS engine.  WEBrick will
          # call it automatically after sending the response header.
          #
          # Also notify the server's attached [[Webtube::Vital_Statistics]]
          # instance so that server shutdown could also close all pending
          # Webtubes.
          define_method :send_body do |socket|
            webtube = Webtube.new(socket, true, close_socket: false)
            begin
              vital_statistics.birth webtube
              webtube.header = request
              webtube.session = session
              webtube.context = context
              # Reassign us from the WEBrick's thread group to the one
              # maintained by [[Webtube::Vital_Statistics]].
              vital_statistics.thread_group.add Thread.current
              # And now, run!
              webtube.run listener
            ensure
              vital_statistics.death webtube
            end
            return
          end
        end
      end
      return
    end
  end

  module HTTPServlet
    class WebtubeHandler < AbstractServlet
      def get_instance server, *options
        return self
      end

      def initialize server, listener
        super server
        @listener = listener
        return
      end

      def do_GET request, response
        if request.websocket_upgrade_request? then
          @server.accept_webtube request, response, @listener
        else
          response.status, response.reason_phrase =
              '426', 'Upgrade to WebSocket'
          response['Sec-WebSocket-Version'] = '13'
              # advertise the version we speak
          # prepare a human-readable content
          response['Content-type'] = 'text/plain'
          response.body = "426\n\nThis is a WebSocket-only resource."
        end
        return
      end
    end
  end

  class HTTPServer
    def mount_webtube dir, listener
      mount dir, HTTPServlet::WebtubeHandler.new(self, listener)
      return
    end
  end
end
