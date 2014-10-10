require 'set'
require 'thread'
require 'webtube'

class Webtube
  # A tracker for live [[Webtube]] instances and their threads.  This allows a
  # shutdowning WEBrick to gently close the pending WebSockets.
  class Vital_Statistics
    # A [[ThreadGroup]] into which the Webtube threads can add themselves.
    # Note that [[Vital_Statistics]] does not forcefully move them (nor could
    # it -- a Webtube does not get a thread before [[Webtube#run]] is called,
    # which is normally _after_ [[Vital_Statistics#birth]] gets called).
    #
    # When Webtube is being integrated with WEBrick by [[webtube/webrick.rb]],
    # assigning Webtube-specific threads into this group will cause WEBrick's
    # standard shutdown procedure to not try to [[Thread#join]] them as it does
    # to ordinary WEBrick threads.  Instead, the integration code will call
    # [[Vital_Statistics#close_all]], to request that each Webtube close
    # itself, and then join the threads from [[Vital_Statistics#thread_group]].
    attr_reader :thread_group

    def initialize logger
      super()
      @logger = logger
      @webtubes = Set.new
      @mutex = Mutex.new
      @thread_group = ThreadGroup.new
      return
    end

    def birth webtube
      @mutex.synchronize do
        @webtubes.add webtube
      end
      return
    end

    def death webtube
      @mutex.synchronize do
        @webtubes.delete webtube
      end
      return
    end

    # The default status code in a shutdown situation is 1001 'going away'.
    def close_all status_code = 1001, explanation = ""
      # Note that we're only mutexing off extracting the content of
      # [[@webtubes]].  We can't mutex the whole block, for as the webtubes
      # will be closing, they'll want to notify us about it, and that is also
      # mutexed.
      #
      # This is not as bad as it may sound, for the webserver shouldn't be
      # accepting new connections anymore anyway by the time it'll start
      # closing the old ones.
      @mutex.synchronize{@webtubes.to_a}.each do |webtube|
        begin
          webtube.close status_code, explanation
        rescue Exception => e
          # log and continue
          logger.error e
        end
      end
      return
    end
  end
end
