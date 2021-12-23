require 'opensearch/transport/transport/connections/selector'

class Fluent::Plugin::OpenSearchFallbackSelector
  include OpenSearch::Transport::Transport::Connections::Selector::Base

  def select(options={})
    connections.first
  end
end
