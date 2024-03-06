
require_relative 'out_opensearch'

module Fluent::Plugin
  class OpenSearchOutputDataStream < OpenSearchOutput

    Fluent::Plugin.register_output('opensearch_data_stream', self)

    helpers :event_emitter

    config_param :data_stream_name, :string
    config_param :data_stream_template_name, :string, :default => nil
    # OpenSearch 1.0 or later always support new style of index template.
    config_set_default :use_legacy_template, false

    INVALID_START_CHRACTERS = ["-", "_", "+", "."]
    INVALID_CHARACTERS = ["\\", "/", "*", "?", "\"", "<", ">", "|", " ", ",", "#", ":"]

    def configure(conf)
      super

      @data_stream_template_name = "#{@data_stream_name}_template" if @data_stream_template_name.nil?

      # ref. https://opensearch.org/docs/latest/opensearch/data-streams/
      unless placeholder?(:data_stream_name_placeholder, @data_stream_name)
        validate_data_stream_parameters
      else
        @use_placeholder = true
        @data_stream_names = []
      end

      unless @use_placeholder
        begin
          @data_stream_names = [@data_stream_name]
          retry_operate(@max_retry_putting_template,
                        @fail_on_putting_template_retry_exceed,
                        @catch_transport_exception_on_retry) do
            create_index_template(@data_stream_name, @data_stream_template_name)
          end
        rescue => e
          raise Fluent::ConfigError, "Failed to create data stream: <#{@data_stream_name}> #{e.message}"
        end
      end
    end

    def validate_data_stream_parameters
      {"data_stream_name" => @data_stream_name,
       "data_stream_template_name" => @data_stream_template_name}.each do |parameter, value|
        unless valid_data_stream_parameters?(value)
          unless start_with_valid_characters?(value)
            if not_dots?(value)
              raise Fluent::ConfigError, "'#{parameter}' must not start with #{INVALID_START_CHRACTERS.join(",")}: <#{value}>"
            else
              raise Fluent::ConfigError, "'#{parameter}' must not be . or ..: <#{value}>"
            end
          end
          unless valid_characters?(value)
            raise Fluent::ConfigError, "'#{parameter}' must not contain invalid characters #{INVALID_CHARACTERS.join(",")}: <#{value}>"
          end
          unless lowercase_only?(value)
            raise Fluent::ConfigError, "'#{parameter}' must be lowercase only: <#{value}>"
          end
          if value.bytes.size > 255
            raise Fluent::ConfigError, "'#{parameter}' must not be longer than 255 bytes: <#{value}>"
          end
        end
      end
    end

    def create_index_template(datastream_name, template_name, host = nil)
      # Create index template from file
      if !dry_run?
        if @template_file
          return if data_stream_exist?(datastream_name, host) or template_exists?(template_name, host)
          template_installation_actual(template_name, @customize_template, @application_name, datastream_name, host)
        else # Create default index template
          return if data_stream_exist?(datastream_name, host) or template_exists?(template_name, host)
          body = {
            "index_patterns" => ["#{datastream_name}*"],
            "data_stream" => {},
          }

          params = {
            name: template_name,
            body: body
          }
          retry_operate(@max_retry_putting_template,
                        @fail_on_putting_template_retry_exceed,
                        @catch_transport_exception_on_retry) do
            client(host).indices.put_index_template(params)
          end
        end
      end
    end

    def data_stream_exist?(datastream_name, host = nil)
      params = {
        name: datastream_name
      }
      begin
        # TODO: Use X-Pack equivalent performing DataStream operation method on the following line
        response = client(host).perform_request('GET', "/_data_stream/#{datastream_name}", {}, params)
        return (not response.is_a?(OpenSearch::Transport::Transport::Errors::NotFound))
      rescue OpenSearch::Transport::Transport::Errors::NotFound => e
        log.info "Specified data stream does not exist. Will be created: <#{e}>"
        return false
      end
    end

    def template_exists?(name, host = nil)
      if @use_legacy_template
        client(host).indices.get_template(:name => name)
      else
        client(host).indices.get_index_template(:name => name)
      end
      return true
    rescue OpenSearch::Transport::Transport::Errors::NotFound
      return false
    end

    def valid_data_stream_parameters?(data_stream_parameter)
      lowercase_only?(data_stream_parameter) and
        valid_characters?(data_stream_parameter) and
        start_with_valid_characters?(data_stream_parameter) and
        not_dots?(data_stream_parameter) and
        data_stream_parameter.bytes.size <= 255
    end

    def lowercase_only?(data_stream_parameter)
      data_stream_parameter.downcase == data_stream_parameter
    end

    def valid_characters?(data_stream_parameter)
      not (INVALID_CHARACTERS.each.any? do |v| data_stream_parameter.include?(v) end)
    end

    def start_with_valid_characters?(data_stream_parameter)
      not (INVALID_START_CHRACTERS.each.any? do |v| data_stream_parameter.start_with?(v) end)
    end

    def not_dots?(data_stream_parameter)
      not (data_stream_parameter == "." or data_stream_parameter == "..")
    end

    def client_library_version
      OpenSearch::VERSION
    end

    def multi_workers_ready?
      true
    end

    def write(chunk)
      data_stream_name = @data_stream_name
      data_stream_template_name = @data_stream_template_name
      host = nil
      if @use_placeholder
        host = if @hosts
                 extract_placeholders(@hosts, chunk)
               else
                 extract_placeholders(@host, chunk)
               end
        data_stream_name = extract_placeholders(@data_stream_name, chunk).downcase
        data_stream_template_name = extract_placeholders(@data_stream_template_name, chunk).downcase
        begin
          create_index_template(data_stream_name, data_stream_template_name, host)
        rescue => e
          raise Fluent::ConfigError, "Failed to create data stream: <#{data_stream_name}> #{e.message}"
        end
      end

      bulk_message = ""
      headers = {
        CREATE_OP => {}
      }
      tag = chunk.metadata.tag
      chunk.msgpack_each do |time, record|
        next unless record.is_a? Hash
        begin
          if record.has_key?(TIMESTAMP_FIELD)
            rts = record[TIMESTAMP_FIELD]
            dt = parse_time(rts, time, tag)
          elsif record.has_key?(@time_key)
            rts = record[@time_key]
            dt = parse_time(rts, time, tag)
          else
            dt = Time.at(time).to_datetime
          end
          record.merge!({"@timestamp" => dt.iso8601(@time_precision)})
          if @include_tag_key
            record[@tag_key] = tag
          end
          if @remove_keys
            @remove_keys.each { |key| record.delete(key) }
          end
          bulk_message = append_record_to_messages(CREATE_OP, {}, headers, record, bulk_message)
        rescue => e
          emit_error_label_event do
            router.emit_error_event(tag, time, record, e)
          end
        end
      end

      return if bulk_message.to_s.empty?

      params = {
        index: data_stream_name,
        body: bulk_message
      }
      begin
        response = client(host).bulk(params)
        if response['errors']
          log.error "Could not bulk insert to Data Stream: #{data_stream_name} #{response}"
        end
      rescue => e
        raise RecoverableRequestFailure, "could not push logs to OpenSearch cluster (#{data_stream_name}): #{e.message}"
      end
    end

    def append_record_to_messages(op, meta, header, record, msgs)
      header[CREATE_OP] = meta
      msgs << @dump_proc.call(header) << BODY_DELIMITER
      msgs << @dump_proc.call(record) << BODY_DELIMITER
      msgs
    end

    def retry_stream_retryable?
      @buffer.storable?
    end
  end
end
