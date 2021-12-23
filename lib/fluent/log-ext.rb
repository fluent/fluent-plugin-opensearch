require 'fluent/log'
# For opensearch-ruby v1.0.0 or later which is based on elasticsearch-ruby v7.14 master tree
# logger for Elasticsearch::Loggable required the following methods:
#
# * debug?
# * info?
# * warn?
# * error?
# * fatal?

module Fluent
  class Log
    # OpenSearch::Loggable does not request trace? method.
    # def trace?
    #   @level <= LEVEL_TRACE
    # end

    def debug?
      @level <= LEVEL_DEBUG
    end

    def info?
      @level <= LEVEL_INFO
    end

    def warn?
      @level <= LEVEL_WARN
    end

    def error?
      @level <= LEVEL_ERROR
    end

    def fatal?
      @level <= LEVEL_FATAL
    end
  end
end
