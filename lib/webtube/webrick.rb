# webtube/webrick.rb -- WEBrick integration for Webtube, an implementation of
# the WebSocket protocol

require 'webrick/httprequest'
require 'webrick/httpserver'
require 'webtube'

class WEBrick::HTTPRequest
  def websocket_upgrade_request?
    return self.request_method.upcase == 'GET' &&
        self.http_version >= '1.1' &&
        (self['Connection'] || '').downcase == 'upgrade' &&
        (self['Upgrade'] || '').downcase == 'websocket' &&
        !self['Sec-WebSocket-Key'].nil?
  end
end

class WEBrick::HTTPServer
  # Given a [[request]] and a [[response]] object, as prepared by a
  # [[WEBrick::HTTPServer]] for processing in a portlet, attempt to accept the
  # client's request to establish a WebSocket connection.  The [[request]] must
  # actually contain such a request; see [[websocket_upgrade_request?]].
  #
  # The attempt will fail in the theoretical case the client and the server
  # can't agree on the protocol version to use.  In such a case,
  # [[accept_webtube]] will prepare a 426 'Upgrade required' response,
  # explaining in plain text what the problem is and advertising, using the
  # [[Sec-WebSocket-Version]] header field, the protocol version (specifically,
  # 13) it is prepared to speak.  When this happens, the WebSocket session will
  # never be set up and no [[listener]] events will be called.
  #
  # Note that [[accept_webtube]] will manipulate [[response]] and return
  # immediately.  The actual WebSocket session will begin once WEBrick attempts
  # to deliver the [[response]], and will be marked by the newly constructed
  # [[Webtube]] instance delivering an [[onopen]] event to [[listener]].
  #
  # Also note that the loop to process incoming WebSocket frames will hog the
  # whole thread; in order to deliver asynchronous messages over the WebSocket,
  # [[Webtube#send_message]] needs to be called from another thread.  (For
  # synchronous messages, it can safely be called from the handlers inside
  # [[listener]].)
  #
  # See [[Webtube::new]] for a list of the supported methods for the
  # [[listener]].
  def accept_webtube request, response, listener
    # Check that the client speaks our version
    unless (request['Sec-WebSocket-Version'] || '').split(/\s*,\s*/).
        include? '13' then
      @logger.error "Sec-WebSocket-Version mismatch"
      response.status, response.reason_phrase = '426', 'Upgrade required'
      response['Content-type'] = 'text/plain'
      response['Sec-WebSocket-Version'] = '13' # advertise the version we speak
      response.body = "This WebSocket server only speaks version 13 of the " +
          "protocol, as specified by RFC 6455.\n"
    else
      response.status, response.reason_phrase = '101', 'Hello WebSocket'
      response['Upgrade'] = 'websocket'
      response['Sec-WebSocket-Accept'] = Digest::SHA1.base64digest(
          request['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      response['Sec-WebSocket-Version'] = '13'
      response.keep_alive = false
          # so that WEBrick will close the TCP socket when we're done
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

        # Replace [[response.send_body]] with the WS engine.  WEBrick will call
        # it automatically after sending the response header.
        define_method :send_body do |socket|
          webtube = Webtube.new(socket, true, close_socket: false)
          webtube.header = request
          webtube.run listener
          return
        end
      end
    end
    return
  end
end
