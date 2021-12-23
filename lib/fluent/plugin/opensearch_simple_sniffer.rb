require 'opensearch'

class Fluent::Plugin::OpenSearchSimpleSniffer < OpenSearch::Transport::Transport::Sniffer

  def hosts
    @transport.logger.debug "In Fluent::Plugin::OpenSearchSimpleSniffer hosts #{@transport.hosts}" if @transport.logger
    @transport.hosts
  end

end
