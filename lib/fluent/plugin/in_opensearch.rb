# SPDX-License-Identifier: Apache-2.0
#
# The fluent-plugin-opensearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright fluent-plugin-opensearch Contributors. See
# GitHub history for details.
#
# Licensed to Uken Inc. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Uken Inc. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require 'opensearch'

require 'faraday/excon'
require 'fluent/log-ext'
require 'fluent/plugin/input'
require 'fluent/plugin_helper'
require_relative 'opensearch_constants'

module Fluent::Plugin
  class OpenSearchInput < Input
    class UnrecoverableRequestFailure < Fluent::UnrecoverableError; end

    DEFAULT_RELOAD_AFTER = -1
    DEFAULT_STORAGE_TYPE = 'local'
    METADATA = "@metadata".freeze

    helpers :timer, :thread, :retry_state

    Fluent::Plugin.register_input('opensearch', self)

    config_param :tag, :string
    config_param :host, :string,  :default => 'localhost'
    config_param :port, :integer, :default => 9200
    config_param :user, :string, :default => nil
    config_param :password, :string, :default => nil, :secret => true
    config_param :path, :string, :default => nil
    config_param :scheme, :enum, :list => [:https, :http], :default => :http
    config_param :hosts, :string, :default => nil
    config_param :index_name, :string, :default => "fluentd"
    config_param :parse_timestamp, :bool, :default => false
    config_param :timestamp_key_format, :string, :default => nil
    config_param :timestamp_parse_error_tag, :string, :default => 'opensearch_plugin.input.time.error'
    config_param :query, :hash, :default => {"sort" => [ "_doc" ]}
    config_param :scroll, :string, :default => "1m"
    config_param :size, :integer, :default => 1000
    config_param :num_slices, :integer, :default => 1
    config_param :interval, :size, :default => 5
    config_param :repeat, :bool, :default => true
    config_param :http_backend, :enum, list: [:excon, :typhoeus], :default => :excon
    config_param :request_timeout, :time, :default => 5
    config_param :reload_connections, :bool, :default => true
    config_param :reload_on_failure, :bool, :default => false
    config_param :resurrect_after, :time, :default => 60
    config_param :reload_after, :integer, :default => DEFAULT_RELOAD_AFTER
    config_param :ssl_verify , :bool, :default => true
    config_param :client_key, :string, :default => nil
    config_param :client_cert, :string, :default => nil
    config_param :client_key_pass, :string, :default => nil, :secret => true
    config_param :ca_file, :string, :default => nil
    config_param :ssl_version, :enum, list: [:SSLv23, :TLSv1, :TLSv1_1, :TLSv1_2], :default => :TLSv1_2
    config_param :with_transporter_log, :bool, :default => false
    config_param :emit_error_label_event, :bool, :default => true
    config_param :sniffer_class_name, :string, :default => nil
    config_param :custom_headers, :hash, :default => {}
    config_param :docinfo_fields, :array, :default => ['_index', '_type', '_id']
    config_param :docinfo_target, :string, :default => METADATA
    config_param :docinfo, :bool, :default => false
    config_param :check_connection, :bool, :default => true
    config_param :retry_forever, :bool, default: true, desc: 'If true, plugin will ignore retry_timeout and retry_max_times options and retry forever.'
    config_param :retry_timeout, :time, default: 72 * 60 * 60, desc: 'The maximum seconds to retry'
    # 72hours == 17 times with exponential backoff (not to change default behavior)
    config_param :retry_max_times, :integer, default: 5, desc: 'The maximum number of times to retry'
    # exponential backoff sequence will be initialized at the time of this threshold
    config_param :retry_type, :enum, list: [:exponential_backoff, :periodic], default: :exponential_backoff
    ### Periodic -> fixed :retry_wait
    ### Exponential backoff: k is number of retry times
    # c: constant factor, @retry_wait
    # b: base factor, @retry_exponential_backoff_base
    # k: times
    # total retry time: c + c * b^1 + (...) + c*b^k = c*b^(k+1) - 1
    config_param :retry_wait, :time, default: 5, desc: 'Seconds to wait before next retry , or constant factor of exponential backoff.'
    config_param :retry_exponential_backoff_base, :float, default: 2, desc: 'The base number of exponential backoff for retries.'
    config_param :retry_max_interval, :time, default: nil, desc: 'The maximum interval seconds for exponential backoff between retries while failing.'
    config_param :retry_randomize, :bool, default: false, desc: 'If true, output plugin will retry after randomized interval not to do burst retries.'

    include Fluent::Plugin::OpenSearchConstants

    def initialize
      super
    end

    def configure(conf)
      super

      @timestamp_parser = create_time_parser
      @backend_options = backend_options
      @retry = nil

      raise Fluent::ConfigError, "`password` must be present if `user` is present" if @user && @password.nil?

      if @user && m = @user.match(/%{(?<user>.*)}/)
        @user = URI.encode_www_form_component(m["user"])
      end
      if @password && m = @password.match(/%{(?<password>.*)}/)
        @password = URI.encode_www_form_component(m["password"])
      end

      @transport_logger = nil
      if @with_transporter_log
        @transport_logger = log
        log_level = conf['@log_level'] || conf['log_level']
        log.warn "Consider to specify log_level with @log_level." unless log_level
      end
      @current_config = nil
      # Specify @sniffer_class before calling #client.
      @sniffer_class = nil
      begin
        @sniffer_class = Object.const_get(@sniffer_class_name) if @sniffer_class_name
      rescue Exception => ex
        raise Fluent::ConfigError, "Could not load sniffer class #{@sniffer_class_name}: #{ex}"
      end

      @options = {
        :index => @index_name,
        :scroll => @scroll,
        :size => @size
      }
      @base_query = @query
    end

    def backend_options
      case @http_backend
      when :excon
        { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
      when :typhoeus
        require 'typhoeus'
        { sslkey: @client_key, sslcert: @client_cert, keypasswd: @client_key_pass }
      end
    rescue LoadError => ex
      log.error_backtrace(ex.backtrace)
      raise Fluent::ConfigError, "You must install #{@http_backend} gem. Exception: #{ex}"
    end

    def retry_state(randomize)
      retry_state_create(
        :input_retries, @retry_type, @retry_wait, @retry_timeout,
        forever: @retry_forever, max_steps: @retry_max_times,
        max_interval: @retry_max_interval, backoff_base: @retry_exponential_backoff_base,
        randomize: randomize
      )
    end

    def get_escaped_userinfo(host_str)
      if m = host_str.match(/(?<scheme>.*)%{(?<user>.*)}:%{(?<password>.*)}(?<path>@.*)/)
        m["scheme"] +
          URI.encode_www_form_component(m["user"]) +
          ':' +
          URI.encode_www_form_component(m["password"]) +
          m["path"]
      else
        host_str
      end
    end

    def get_connection_options(con_host=nil)

      hosts = if con_host || @hosts
        (con_host || @hosts).split(',').map do |host_str|
          # Support legacy hosts format host:port,host:port,host:port...
          if host_str.match(%r{^[^:]+(\:\d+)?$})
            {
              host:   host_str.split(':')[0],
              port:   (host_str.split(':')[1] || @port).to_i,
              scheme: @scheme.to_s
            }
          else
            # New hosts format expects URLs such as http://logs.foo.com,https://john:pass@logs2.foo.com/elastic
            uri = URI(get_escaped_userinfo(host_str))
            %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
              hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
              hash
            end
          end
        end.compact
      else
        [{host: @host, port: @port, scheme: @scheme.to_s}]
      end.each do |host|
        host.merge!(user: @user, password: @password) if !host[:user] && @user
        host.merge!(path: @path) if !host[:path] && @path
      end
      live_hosts = @check_connection ? hosts.select { |host| reachable_host?(host) } : hosts
      {
        hosts: live_hosts
      }
    end

    def reachable_host?(host)
      client = OpenSearch::Client.new(
        host: ["#{host[:scheme]}://#{host[:host]}:#{host[:port]}"],
        user: host[:user],
        password: host[:password],
        reload_connections: @reload_connections,
        request_timeout: @request_timeout,
        resurrect_after: @resurrect_after,
        reload_on_failure: @reload_on_failure,
        transport_options: { ssl: { verify: @ssl_verify, ca_file: @ca_file, version: @ssl_version } }
      )
      client.ping
    rescue => e
      log.warn "Failed to connect to #{host[:scheme]}://#{host[:host]}:#{host[:port]}: #{e.message}"
      false
    end

    def emit_error_label_event(&block)
      # If `emit_error_label_event` is specified as false, error event emittions are not occurred.
      if emit_error_label_event
        block.call
      end
    end

    def start
      super

      timer_execute(:in_opensearch_timer, @interval, repeat: @repeat, &method(:run))
    end

    # We might be able to use
    # Fluent::Parser::TimeParser, but it doesn't quite do what we want - if gives
    # [sec,nsec] where as we want something we can call `strftime` on...
    def create_time_parser
      if @timestamp_key_format
        begin
          # Strptime doesn't support all formats, but for those it does it's
          # blazingly fast.
          strptime = Strptime.new(@timestamp_key_format)
          Proc.new { |value|
            value = convert_numeric_time_into_string(value, @timestamp_key_format) if value.is_a?(Numeric)
            strptime.exec(value).to_time
          }
        rescue
          # Can happen if Strptime doesn't recognize the format; or
          # if strptime couldn't be required (because it's not installed -- it's
          # ruby 2 only)
          Proc.new { |value|
            value = convert_numeric_time_into_string(value, @timestamp_key_format) if value.is_a?(Numeric)
            DateTime.strptime(value, @timestamp_key_format).to_time
          }
        end
      else
        Proc.new { |value|
          value = convert_numeric_time_into_string(value) if value.is_a?(Numeric)
          DateTime.parse(value).to_time
        }
      end
    end

    def convert_numeric_time_into_string(numeric_time, timestamp_key_format = "%Y-%m-%dT%H:%M:%S.%N%z")
      numeric_time_parser = Fluent::NumericTimeParser.new(:float)
      Time.at(numeric_time_parser.parse(numeric_time).to_r).strftime(timestamp_key_format)
    end

    def parse_time(value, event_time, tag)
      @timestamp_parser.call(value)
    rescue => e
      emit_error_label_event do
        router.emit_error_event(@timestamp_parse_error_tag, Fluent::Engine.now, {'tag' => tag, 'time' => event_time, 'format' => @timestamp_key_format, 'value' => value}, e)
      end
      return Time.at(event_time).to_time
    end

    def client(host = nil)
      # check here to see if we already have a client connection for the given host
      connection_options = get_connection_options(host)

      @_os = nil unless is_existing_connection(connection_options[:hosts])

      @_os ||= begin
        @current_config = connection_options[:hosts].clone
        adapter_conf = lambda {|f| f.adapter @http_backend, @backend_options }
        local_reload_connections = @reload_connections
        if local_reload_connections && @reload_after > DEFAULT_RELOAD_AFTER
          local_reload_connections = @reload_after
        end

        headers = { 'Content-Type' => "application/json" }.merge(@custom_headers)

        transport = OpenSearch::Transport::Transport::HTTP::Faraday.new(
          connection_options.merge(
            options: {
              reload_connections: local_reload_connections,
              reload_on_failure: @reload_on_failure,
              resurrect_after: @resurrect_after,
              logger: @transport_logger,
              transport_options: {
                headers: headers,
                request: { timeout: @request_timeout },
                ssl: { verify: @ssl_verify, ca_file: @ca_file, version: @ssl_version }
              },
              http: {
                user: @user,
                password: @password
              },
              sniffer_class: @sniffer_class,
            }), &adapter_conf)
        OpenSearch::Client.new transport: transport
      end
    end

    def is_existing_connection(host)
      # check if the host provided match the current connection
      return false if @_os.nil?
      return false if @current_config.nil?
      return false if host.length != @current_config.length

      for i in 0...host.length
        if !host[i][:host].eql? @current_config[i][:host] || host[i][:port] != @current_config[i][:port]
          return false
        end
      end

      return true
    end

    def update_retry_state(error=nil)
      if error
        unless @retry
          @retry = retry_state(@retry_randomize)
        end
        @retry.step
        #Raise error if the retry limit has been reached
        raise "Hit limit for retries. retry_times: #{@retry.steps}, error: #{error.message}" if @retry.limit?
        #Retry if the limit hasn't been reached
        log.warn("failed to connect or search.", retry_times: @retry.steps, next_retry_time: @retry.next_time.round, error: error.message)
        sleep(@retry.next_time - Time.now)
      else
        unless @retry.nil?
          log.debug("retry succeeded.")
          @retry = nil
        end
      end
    end

    def run
      return run_slice if @num_slices <= 1

      log.warn("Large slice number is specified:(#{@num_slices}). Consider reducing num_slices") if @num_slices > 8

      @num_slices.times.map do |slice_id|
        thread_create(:"in_opensearch_thread_#{slice_id}") do
          run_slice(slice_id)
        end
      end
    rescue Faraday::ConnectionFailed, OpenSearch::Transport::Transport::Error => error
      update_retry_state(error)
      retry
    end

    def run_slice(slice_id=nil)
      slice_query = @base_query
      slice_query = slice_query.merge('slice' => { 'id' => slice_id, 'max' => @num_slices}) unless slice_id.nil?
      result = client.search(@options.merge(:body => Yajl.dump(slice_query) ))
      es = Fluent::MultiEventStream.new

      result["hits"]["hits"].each {|hit| process_events(hit, es)}
      has_hits = result['hits']['hits'].any?
      scroll_id = result['_scroll_id']

      while has_hits && scroll_id
        result = process_next_scroll_request(es, scroll_id)
        has_hits = result['has_hits']
        scroll_id = result['_scroll_id']
      end

      router.emit_stream(@tag, es)
      clear_scroll(scroll_id)
      update_retry_state
    end

    def clear_scroll(scroll_id)
      client.clear_scroll(scroll_id: scroll_id) if scroll_id
    rescue => e
      # ignore & log any clear_scroll errors
      log.warn("Ignoring clear_scroll exception", message: e.message, exception: e.class)
    end

    def process_scroll_request(scroll_id)
      client.scroll(:body => { :scroll_id => scroll_id }, :scroll => @scroll)
    end

    def process_next_scroll_request(es, scroll_id)
      result = process_scroll_request(scroll_id)
      result['hits']['hits'].each { |hit| process_events(hit, es) }
      {'has_hits' => result['hits']['hits'].any?, '_scroll_id' => result['_scroll_id']}
    end

    def process_events(hit, es)
      event = hit["_source"]
      time = Fluent::Engine.now
      if @parse_timestamp
        if event.has_key?(TIMESTAMP_FIELD)
          rts = event[TIMESTAMP_FIELD]
          time = parse_time(rts, time, @tag)
        end
      end
      if @docinfo
        docinfo_target = event[@docinfo_target] || {}

        unless docinfo_target.is_a?(Hash)
          raise UnrecoverableError, "incompatible type for the docinfo_target=#{@docinfo_target} field in the `_source` document, expected a hash got:", :type => docinfo_target.class, :event => event
        end

        @docinfo_fields.each do |field|
          docinfo_target[field] = hit[field]
        end

        event[@docinfo_target] = docinfo_target
      end
      es.add(time, event)
    end
  end
end
