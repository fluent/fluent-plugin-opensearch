require 'fluent/error'

class Fluent::Plugin::OpenSearchError
  class RetryableOperationExhaustedFailure < Fluent::UnrecoverableError; end
end
