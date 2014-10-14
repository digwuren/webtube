# webtube.rb -- an implementation of the WebSocket extension of HTTP

require 'base64'
require 'digest/sha1'
require 'net/http'
require 'securerandom'
require 'thread'
require 'uri'
require 'webrick/httprequest'

class Webtube
  # Not all the possible 16 values are defined by the standard.
  OPCODE_CONTINUATION  = 0x0
  OPCODE_TEXT          = 0x1
  OPCODE_BINARY        = 0x2
  OPCODE_CLOSE         = 0x8
  OPCODE_PING          = 0x9
  OPCODE_PONG          = 0xA

  attr_accessor :allow_rsv_bits
  attr_accessor :allow_opcodes

  # The following three slots are not used by the [[Webtube]] infrastructrue.
  # They have been defined purely so that application code could easily
  # associate data it finds significant to [[Webtube]] instances.

  attr_accessor :header # [[accept_webtube]] saves the request object here
  attr_accessor :session
  attr_accessor :context

  def initialize socket,
      serverp,
          # If true, we will expect incoming data masked and will not mask
          # outgoing data.  If false, we will expect incoming data unmasked and
          # will mask outgoing data.
      allow_rsv_bits: 0,
      allow_opcodes: [Webtube::OPCODE_TEXT, Webtube::OPCODE_BINARY],
      close_socket: true
    super()
    @socket = socket
    @serverp = serverp
    @allow_rsv_bits = allow_rsv_bits
    @allow_opcodes = allow_opcodes
    @close_socket = close_socket
    @defrag_buffer = []
    @alive = true
    @send_mutex = Mutex.new
        # Guards message sending, so that fragmented messages won't get
        # interleaved, and the [[@alive]] flag.
    @run_mutex = Mutex.new
        # Guards the main read loop.
    @receiving_frame = false
        # Are we currently receiving a frame for the [[Webtube#run]] main loop?
    @reception_interrupt_mutex = Mutex.new
        # guards [[@receiving_frame]]
    return
  end

  # Run a loop to read all the messages and control frames coming in via this
  # WebSocket, and hand events to the given [[listener]].  The listener can
  # implement the following methods:
  #
  # - onopen(webtube) will be called as soon as the channel is set up.
  #
  # - onmessage(webtube, message_body, opcode) will be called with each
  #   arriving data message once it has been defragmented.  The data will be
  #   passed to it as a [[String]], encoded in [[UTF-8]] for [[OPCODE_TEXT]]
  #   messages and in [[ASCII-8BIT]] for all the other message opcodes.
  #
  # - onannoyedclose(webtube, frame) will be called upon receipt of an
  #   [[OPCODE_CLOSE]] frame with an explicit status code other than 1000.
  #   This typically indicates that the other side is annoyed, so the listener
  #   may want to log the condition for debugging or further analysis.
  #   Normally, once the handler returns, [[Webtube]] will respond with a close
  #   frame of the same status code and close the connection, but the handler
  #   may call [[Webtube#close]] to request a closure with a different status
  #   code or without one.
  #
  # - onping(webtube, frame) will be called upon receipt of an [[OPCODE_PING]]
  #   frame.  [[Webtube]] will take care of ponging all the pings, but the
  #   listener may want to process such an event for statistical information.
  #
  # - onpong(webtube, frame) will be called upon receipt of an [[OPCODE_PONG]]
  #   frame.
  #
  # - onclose(webtube) will be called upon closure of the connection, for any
  #   reason.
  #
  # - onexception(webtube, exception) will be called if an unhandled exception
  #   is raised during the [[Webtube]]'s lifecycle, including all of the
  #   listener event handlers.  It may log the exception but should return
  #   normally so that the [[Webtube]] can issue a proper close frame for the
  #   other end and invoke the [[onclose]] handler, after which the exception
  #   will be raised again so the caller of [[Webtube::new]] will have a chance
  #   of handling it.
  #
  # Before calling any of the handlers, [[respond_to?]] will be used to check
  # implementedness.
  #
  # If an exception occurs during processing, it may implement a specific
  # status code to be passed to the other end via the [[OPCODE_CLOSE]] frame by
  # implementing the [[websocket_close_status_code]] method returning the code
  # as an integer.  The default code, used if the exception does not specify
  # one, is 1011 'unexpected condition'.  An exception may explicitly suppress
  # sending any code by having [[websocket_close_status_code]] return [[nil]]
  # instead of an integer.
  #
  def run listener
    @run_mutex.synchronize do
      @thread = Thread.current
      begin
        listener.onopen self if listener.respond_to? :onopen
        while @send_mutex.synchronize{@alive} do
          begin
            @reception_interrupt_mutex.synchronize do
              @receiving_frame = true
            end
            frame = Webtube::Frame.read_from_socket @socket
          ensure
            @reception_interrupt_mutex.synchronize do
              @receiving_frame = false
            end
          end
          unless (frame.rsv & ~@allow_rsv_bits) == 0 then
            raise Webtube::UnknownReservedBit.new(frame: frame)
          end
          if @serverp then
            unless frame.masked?
              raise Webtube::UnmaskedFrameToServer.new(frame: frame)
            end
          else
            unless !frame.masked? then
              raise Webtube::MaskedFrameToClient.new(frame: frame)
            end
          end
          if !frame.control_frame? then
            # data frame
            if frame.opcode != Webtube::OPCODE_CONTINUATION then
              # initial frame
              unless @allow_opcodes.include? frame.opcode then
                raise Webtube::UnknownOpcode.new(frame: frame)
              end
              unless @defrag_buffer.empty? then
                raise Webtube::MissingContinuationFrame.new
              end
            else
              # continuation frame
              if @defrag_buffer.empty? then
                raise Webtube::UnexpectedContinuationFrame.new(frame: frame)
              end
            end
            @defrag_buffer.push frame
            if frame.fin? then
              opcode = @defrag_buffer.first.opcode
              data = @defrag_buffer.map(&:payload).join ''
              @defrag_buffer = []
              if opcode == Webtube::OPCODE_TEXT then
                # text messages must be encoded in UTF-8, as per RFC 6455
                data.force_encoding 'UTF-8'
                unless data.valid_encoding? then
                  data.force_encoding 'ASCII-8BIT'
                  raise Webtube::BadlyEncodedText.new(data: data)
                end
              end
              listener.onmessage self, data, opcode \
                  if listener.respond_to? :onmessage
            end
          elsif (0x08 .. 0x0F).include? frame.opcode then
            # control frame
            unless frame.fin? then
              raise Webtube::FragmentedControlFrame.new(frame: frame)
            end
            case frame.opcode
            when Webtube::OPCODE_CLOSE then
              message = frame.payload
              if message.length >= 2 then
                status_code, = message.unpack 'n'
                unless status_code == 1000 then
                  listener.onannoyedclose self, frame \
                      if listener.respond_to? :onannoyedclose
                end
              else
                status_code = 1000
              end
              close status_code
            when Webtube::OPCODE_PING then
              listener.onping self, frame if listener.respond_to? :onping
              send_message frame.payload, Webtube::OPCODE_PONG
            when Webtube::OPCODE_PONG then
              listener.onpong self, frame if listener.respond_to? :onpong
              # ignore
            else
              raise Webtube::UnknownOpcode.new(frame: frame)
            end
          else
            raise 'assertion failed'
          end
        end
      rescue AbortReceiveLoop
        # we're out of the loop now, so nothing further to do
      rescue Exception => e
        status_code = if e.respond_to? :websocket_close_status_code then
          e.websocket_close_status_code
        else
          1011 # 'unexpected condition'
        end
        listener.onexception self, e if listener.respond_to? :onexception
        begin
          close status_code
        rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ENOTCONN
          # ignore, we have a bigger exception to handle
        end
        raise e
      ensure
        @thread = nil
        listener.onclose self if listener.respond_to? :onclose
      end
    end
    return
  end

  # Send a given message payload to the other party, using the given opcode.
  # By default, the [[opcode]] is [[Webtube::OPCODE_TEXT]].  Re-encodes the
  # payload if given in a non-UTF-8 encoding and [[opcode ==
  # Webtube::OPCODE_TEXT]].
  def send_message message, opcode = Webtube::OPCODE_TEXT
    if opcode == Webtube::OPCODE_TEXT and message.encoding.name != 'UTF-8' then
      message = message.encode 'UTF-8'
    end
    @send_mutex.synchronize do
      raise 'WebSocket connection no longer live' unless @alive
      # In order to ensure that the local kernel will treat our (data) frames
      # atomically during the [[write]] syscall, we'll want to ensure that the
      # frame size does not exceed 512 bytes -- the minimum permitted size for
      # [[PIPE_BUF]].  At this frame size, the header size is up to four bytes
      # for unmasked or eight bytes for masked frames.
      Webtube::Frame.each_frame_for_message(
          message: message,
          opcode: opcode,
          masked: !@serverp,
          max_frame_body_size: 512 - (!@serverp ? 8 : 4)) do |frame|
        @socket.write frame.header + frame.body
      end
    end
    return
  end

  # Close the connection, thus preventing further processing.
  #
  # If [[status_code]] is supplied, it will be passed to the other side in the
  # [[OPCODE_CLOSE]] frame.  The default is 1000 which indicates normal
  # closure.  Sending a status code can be explicitly suppressed by passing
  # [[nil]] instead of an integer; then, an empty close frame will be sent.
  # Due to the way a close frame's payload is structured, this will also
  # suppress delivery of [[close_explanation]], even if non-empty.
  #
  # Note that RFC 6455 requires the explanation to be encoded in UTF-8.
  # Accordingly, this method will re-encode it unless it is already in UTF-8.
  def close status_code = 1000, explanation = ""
    # prepare the payload for the close frame
    payload = ""
    if status_code then
      payload = [status_code].pack('n')
      if explanation then
        payload << explanation.encode('UTF-8')
      end
    end
    # let the other side know we're closing
    send_message payload, OPCODE_CLOSE
    # break the main reception loop
    @send_mutex.synchronize do
      @alive = false
    end
    # if waiting for a frame (or parsing one), interrupt it
    @reception_interrupt_mutex.synchronize do
      @thread.raise AbortReceiveLoop.new if @receiving_frame
    end
    @socket.close if @close_socket
    return
  end

  # Attempt to set up a [[WebSocket]] connection to the given [[url]].  Return
  # the [[Webtube]] instance if successful or raise an appropriate
  # [[Webtube::WebSocketUpgradeFailed]].
  def self::connect url,
      header_fields: {},
      ssl_verify_mode: nil,
      on_http_response: nil,
      allow_rsv_bits: 0,
      allow_opcodes: [Webtube::OPCODE_TEXT, Webtube::OPCODE_BINARY],
      close_socket: true
    # We'll replace the WebSocket protocol prefix with an HTTP-based one so
    # [[URI::parse]] would know how to parse the rest of the URL.
    case url
      when /\Aws:/ then
        hturl = 'http:' + $'
        ssl = false
        default_port = 80
      when /\Awss:/ then
        hturl = 'https:' + $'
        ssl = true
        default_port = 443
      else
        raise "unknown URI scheme; use ws: or wss: instead"
    end
    hturi = URI.parse hturl

    reqhdr = {}

    # Copy over the user-supplied header fields.  Since Ruby hashes are
    # case-sensitive but HTTP header field names are case-insensitive, we may
    # have to combine fields whose names only differ in case.
    header_fields.each_pair do |name, value|
      name = name.downcase
      if reqhdr.has_key? name then
        reqhdr[name] += ', ' + value
      else
        reqhdr[name] = value
      end
    end

    # Set up the WebSocket header fields (but we'll give user-specified values,
    # if any, precedence)
    reqhdr['host'] ||=
        hturi.host + (hturi.port != default_port ? ":#{hturi.port}" : "")
    reqhdr['upgrade'] ||= 'websocket'
    reqhdr['connection'] ||= 'upgrade'
    reqhdr['sec-websocket-key'] ||= SecureRandom.base64(16)
    reqhdr['sec-websocket-version'] ||= '13'

    start_options = {}
    start_options[:use_ssl] = ssl
    start_options[:verify_mode] = ssl_verify_mode if ssl and ssl_verify_mode
    http = Net::HTTP.start hturi.host, hturi.port, **start_options

    object_to_request = hturi.path
    if object_to_request.empty? then
      object_to_request = '/'
    end
    if hturi.query then
      object_to_request += '?' + hturi.query
    end
    response = http.get object_to_request, reqhdr
    on_http_response.call response if on_http_response

    # Check that the server is seeing us now
    unless response.code == '101' then
      raise Webtube::WebSocketDeclined.new("the HTTP response code was not 101")
    end
    unless (response['Connection'] || '').downcase == 'upgrade' then
      raise Webtube::WebSocketDeclined.new("the HTTP response did not say " +
          "'Connection: upgrade'")
    end
    unless (response['Upgrade'] || '').downcase == 'websocket' then
      raise Webtube::WebSocketDeclined.new("the HTTP response did not say " +
          "'Upgrade: websocket'")
    end
    expected_accept = Digest::SHA1.base64digest(
        reqhdr['sec-websocket-key'] +
        '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    unless (response['Sec-WebSocket-Accept'] || '') == expected_accept then
      raise Webtube::WebSocketDeclined.new("the HTTP response did not say " +
          "'Sec-WebSocket-Accept: #{expected_accept}'")
    end
    unless (response['Sec-WebSocket-Version'] || '13').
        split(/\s*,\s*/).include? '13' then
      raise Webtube::WebSocketVersionMismatch.new(
          "Sec-WebSocket-Version negotiation failed")
    end

    # The connection has been set up.  Now let's set up the Webtube.
    socket = http.instance_eval{@socket}
    socket.read_timeout = nil # turn off timeout
    return Webtube.new socket, false,
        allow_rsv_bits: allow_rsv_bits,
        allow_opcodes: allow_opcodes,
        close_socket: close_socket
  end

  # The application may want to store many Webtube instances in a hash or a
  # set.  In order to facilitate this, we'll need [[hash]] and [[eql?]].  The
  # latter is already adequately -- comparing by identity -- implemented by
  # [[Object]]; in order to ensure the former hashes by identity, we'll
  # override it.
  def hash
    return object_id
  end

  # A technical exception, raised by [[Webtube#close]] if [[Webtube#run]] is
  # currently waiting for a frame.
  class AbortReceiveLoop < Exception
  end

  # Note that [[body]] holds the /raw/ data; that is, if [[masked?]] is true,
  # it will need to be unmasked to get the payload.  Call [[payload]] in order
  # to abstract this away.
  Frame = Struct.new(:header, :body)
  class Frame
    def fin?
      return (header.getbyte(0) & 0x80) != 0
    end

    def fin= new_value
      header.setbyte 0, header.getbyte(0) & 0x7F | (new_value ? 0x80 : 0x00)
      return new_value
    end

    def rsv1
      return (header.getbyte(0) & 0x40) != 0
    end

    def rsv2
      return (header.getbyte(0) & 0x20) != 0
    end

    def rsv3
      return (header.getbyte(0) & 0x10) != 0
    end

    # The three reserved bits of the frame, shifted rightwards to meet the
    # binary point
    def rsv
      return (header.getbyte(0) & 0x70) >> 4
    end

    def opcode
      return header.getbyte(0) & 0x0F
    end

    def opcode= new_opcode
      header.setbyte 0, (header.getbyte(0) & ~0x0F) | (new_opcode & 0x0F)
      return new_opcode
    end

    def control_frame?
      return opcode >= 0x8
    end

    def masked?
      return (header.getbyte(1) & 0x80) != 0
    end

    # Determine the size of this frame's extended payload length field in bytes
    # from the 7-bit short payload length field.
    def extended_payload_length_field_size
      return case header.getbyte(1) & 0x7F
        when 126 then 2
        when 127 then 8
        else 0
      end
    end

    # Extract the length of this frame's payload.  Enough bytes of the header
    # must already have been read; see [[extended_payload_lenth_field_size]].
    def payload_length
      return case base = header.getbyte(1) & 0x7F
        when 126 then header.unpack('@2 n').first
        when 127 then header.unpack('@2 @>').first
        else base
      end
    end

    # Extract the mask as a 4-byte [[ASCII-8BIT]] string from this frame.  If
    # the frame has the [[masked?]] bit unset, return [[nil]] instead.
    def mask
      if masked? then
        mask_offset = 2 + case header.getbyte(1) & 0x7F
          when 126 then 2
          when 127 then 8
          else 0
        end
        return header[mask_offset, 4]
      else
        return nil
      end
    end

    # Extract the frame's payload and return it as a [[String]] instance of the
    # [[ASCII-8BIT]] encoding.  If the frame has the [[masked?]] bit set, this
    # also involves demasking.
    def payload
      return Frame.apply_mask(body, mask)
    end

    # Apply the given [[mask]], specified as a four-byte (!) [[String]], to the
    # given [[data]].  Note that since the underlying operation is [[XOR]], the
    # operation can be repeated to reverse itself.
    #
    # [[nil]] can be supplied instead of [[mask]] to indicate that no
    # processing is needed.
    #
    def self::apply_mask data, mask
      return data if mask.nil?
      raise 'invalid mask' unless mask.bytesize == 4
      result = data.dup
      (0 ... result.bytesize).each do |i|
        result.setbyte i, result.getbyte(i) ^ mask.getbyte(i & 3)
      end
      return result
    end

    # Read all the bytes of one WebSocket frame from the given [[socket]] and
    # return them in a [[Frame]] instance.  In case traffic ends before the
    # frame is complete, raise [[BrokenFrame]].
    #
    # Note that this will call [[socket.read]] twice or thrice, and assumes no
    # other thread will consume bytes from the socket inbetween.  In a
    # multithreaded environment, it may be necessary to apply external
    # locking.
    #
    # If EOF happens before the frame will be completely read, will raise
    # [[Webtube::BrokenFrame]].
    #
    def self::read_from_socket socket
      header = socket.read(2)
      unless header and header.bytesize == 2 then
        header ||= String.new.force_encoding('ASCII-8BIT')
        raise BrokenFrame.new(header)
      end
      frame = Frame.new header

      header_tail_size = frame.extended_payload_length_field_size +
          (frame.masked? ? 4 : 0)
      unless header_tail_size.zero? then
        header_tail = socket.read(header_tail_size)
        frame.header << header_tail if header_tail
        unless header_tail and header_tail.bytesize == header_tail_size then
          raise BrokenFrame.new(frame.header)
        end
      end

      data_size = frame.payload_length
      frame.body = socket.read(data_size)
      unless frame.body and frame.body.bytesize == data_size then
        raise BrokenFrame.new(frame.body ?
            frame.header + frame.body :
            frame.header)
      end

      return frame
    end

    # Given a frame's payload, prepare the header and return a [[Frame]]
    # instance representing such a frame.  Optionally, some header fields can
    # also be set.
    #
    # It's OK for the caller to modify some header fields, such as [[fin]] or
    # [[opcode]], on the returned [[Frame]] by calling the appropriate methods.
    # Its body should not be modified after construction, however, because its
    # length and possibly its mask is already encoded in the header.
    def self::prepare(
        payload: '',
        opcode: OPCODE_TEXT,
        fin: true,
        masked: false)
      header = [0].pack 'C' # we'll fill out the first byte later
      mask_flag = masked ? 0x80 : 0x00
      header << if payload.bytesize <= 125 then
        [mask_flag | payload.bytesize].pack 'C'
      elsif payload.bytesize <= 0xFFFF then
        [mask_flag | 126, payload.bytesize].pack 'n'
      elsif payload.bytesize <= 0x7FFF_FFFF_FFFF_FFFF then
        [mask_flag | 127, payload.bytesize].pack 'Q>'
      else
        raise 'attempted to prepare a WebSocket frame with too big payload'
      end
      frame = Frame.new(header)
      unless masked then
        frame.body = payload
      else
        mask = SecureRandom.random_bytes(4)
        frame.header << mask
        frame.body = apply_mask(payload, mask)
      end

      # now, it's time to fill out the first byte
      frame.fin = fin
      frame.opcode = opcode

      return frame
    end

    # Given a message and attributes, break it up into frames, and yields each
    # such [[Frame]] separately for processing by the caller -- usually,
    # delivery to the other end via the socket.  Takes care to not fragment
    # control messages.  If masking is required, uses
    # [[SecureRandom.random_bytes]] to generate masks for each frame.
    def self::each_frame_for_message message: '',
        opcode: OPCODE_TEXT,
        masked: false,
        max_frame_body_size: nil
      message = message.dup.force_encoding Encoding::ASCII_8BIT
      offset = 0
      fin = true
      begin
        frame_length = message.bytesize - offset
        fin = !(opcode <= 0x07 and
            max_frame_body_size and
            frame_length > max_frame_body_size)
        frame_length = max_frame_body_size unless fin
        yield Webtube::Frame.prepare(
            opcode: opcode,
            payload: message[offset, frame_length],
            fin: fin,
            masked: masked)
        offset += frame_length
        opcode = 0x00 # for continuation frames
      end until fin
      return
    end
  end

  class ConnectionNotAlive < RuntimeError
    def initialize
      super "WebSocket connection is no longer alive and can not transmit " +
          "any more messages"
      return
    end
  end

  class ProtocolError < StandardError
    def websocket_close_status_code
      return 1002
    end
  end

  # Indicates that a complete frame could not be read from the underlying TCP
  # connection.  [[Webtube::Frame::read_from_socket]] will also give it the
  # partial frame as a string so it could be further analysed, but this is
  # optional.
  class BrokenFrame < ProtocolError
    attr_reader :partial_frame

    def initialize message = "no complete WebSocket frame was available",
        partial_frame = nil
      super message
      @partial_frame = partial_frame
      return
    end
  end

  class UnknownReservedBit < ProtocolError
    attr_reader :frame

    def initialize message = "frame with unknown RSV bit arrived",
        frame: nil
      super message
      @frame = frame
      return
    end

    def websocket_close_status_code
      return 1003
    end
  end

  class UnknownOpcode < ProtocolError
    attr_reader :frame

    def initialize message = "frame with unknown opcode arrived",
        frame: nil
      super message
      @frame = frame
      return
    end

    def websocket_close_status_code
      return 1003
    end
  end

  class UnmaskedFrameToServer < ProtocolError
    attr_reader :frame

    def initialize message = "unmasked frame arrived but we're the server",
        frame: nil
      super message
      @frame = frame
      return
    end
  end

  class MaskedFrameToClient < ProtocolError
    attr_reader :frame

    def initialize message = "masked frame arrived but we're the client",
        frame: nil
      super message
      @frame = frame
      return
    end
  end

  class MissingContinuationFrame < ProtocolError
    def initialize message = "a new initial data frame arrived while only " +
        "parts of a previous fragmented message had arrived"
      super message
      return
    end
  end

  class UnexpectedContinuationFrame < ProtocolError
    attr_reader :frame

    def initialize message = "a continuation frame arrived but there was no " +
        "fragmented message pending",
        frame: nil
      super message
      @frame = frame
      return
    end
  end

  class BadlyEncodedText < ProtocolError
    attr_reader :data

    def initialize message = "invalid UTF-8 in a text-type message",
        data: data
      super message
      @data = data
      return
    end

    def websocket_close_status_code
      return 1007
    end
  end

  class FragmentedControlFrame < ProtocolError
    attr_reader :frame

    def initialize message = "a control frame arrived without its FIN flag set",
        frame: nil
      super message
      @frame = frame
      return
    end
  end

  class WebSocketUpgradeFailed < StandardError
  end

  class WebSocketDeclined < WebSocketUpgradeFailed
  end

  class WebSocketVersionMismatch < WebSocketUpgradeFailed
  end
end
