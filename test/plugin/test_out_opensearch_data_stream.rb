require_relative '../helper'
require 'date'
require 'fluent/test/helpers'
require 'fluent/test/driver/output'
require 'flexmock/test_unit'
require 'fluent/plugin/out_opensearch_data_stream'

class OpenSearchOutputDataStreamTest < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  attr_accessor :bulk_records, :index_cmds

  OPENSEARCH_DATA_STREAM_TYPE = "opensearch_data_stream"

  def setup
    Fluent::Test.setup
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
    @bulk_records = 0
  end

  def driver(conf='', os_version=1, client_version="\"1.0\"")
    # For request stub to detect compatibility.
    @os_version ||= os_version
    @client_version ||= client_version
    Fluent::Plugin::OpenSearchOutputDataStream.module_eval(<<-CODE)
      def detect_os_major_version
        #{@os_version}
      end
    CODE
    @driver ||= Fluent::Test::Driver::Output.new(Fluent::Plugin::OpenSearchOutputDataStream) {
      # v0.12's test driver assume format definition. This simulates ObjectBufferedOutput format
      if !defined?(Fluent::Plugin::Output)
        def format(tag, time, record)
          [time, record].to_msgpack
        end
      end
    }.configure(conf)
  end

  def sample_data_stream
    {
      'data_streams': [
                        {
                          'name' => 'foo',
                          'timestamp_field' => {
                            'name' => '@timestamp'
                          }
                        }
                      ]
    }
  end

  def sample_record
    {'@timestamp' => Time.now.iso8601, 'message' => 'Sample record'}
  end

  RESPONSE_ACKNOWLEDGED = {"acknowledged": true}
  DUPLICATED_DATA_STREAM_EXCEPTION = {"error": {}, "status": 400}
  NONEXISTENT_DATA_STREAM_EXCEPTION = {"error": {}, "status": 404}

  def stub_index_template(name="foo_tpl", url="http://localhost:9200")
    stub_request(:put, "#{url}/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_data_stream(name="foo", url="localhost:9200")
    stub_request(:put, "#{url}/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_data_stream?(name="foo", url="localhost:9200")
    stub_request(:get, "#{url}/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_template?(name="foo_tpl", url="localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_nonexistent_data_stream?(name="foo", url="localhost:9200")
    stub_request(:get, "#{url}/_data_stream/#{name}").to_return(:status => [404, OpenSearch::Transport::Transport::Errors::NotFound])
  end

  def stub_nonexistent_template?(name="foo_tpl", url="http://localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").to_return(:status => [404, OpenSearch::Transport::Transport::Errors::NotFound])
  end

  def stub_nonexistent_template_retry?(name="foo_tpl", url="http://localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").
      to_return({ status: 500, body: 'Internal Server Error' }, { status: 404, body: '{}' })
  end

  def stub_bulk_feed(datastream_name="foo", template_name="foo_tpl", url="http://localhost:9200")
    stub_request(:post, "#{url}/#{datastream_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_data_stream/foo_bar
      # {"@timestamp": ...}
      @bulk_records += req.body.split("\n").size / 2
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end
    stub_request(:post, "http://#{url}#{template_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_data_stream/foo_bar
      # {"@timestamp": ...}
      @bulk_records += req.body.split("\n").size / 2
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end
  end

  def stub_opensearch_info(url="http://localhost:9200/", version="1.2.2", headers={})
    body ="{\"version\":{\"number\":\"#{version}\", \"distribution\":\"opensearch\"},\"tagline\":\"The OpenSearch Project: https://opensearch.org/\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json' }.merge(headers) })
  end

  def stub_default(datastream_name="foo", template_name="foo_tpl", host="http://localhost:9200")
    stub_opensearch_info(host)
    stub_nonexistent_template?(template_name)
    stub_index_template(template_name)
    stub_nonexistent_data_stream?(datastream_name)
    stub_data_stream(datastream_name)
  end

  def stub_opensearch_with_store_index_command_counts(url="http://localhost:9200/_bulk")
    if @index_command_counts == nil
      @index_command_counts = {}
      @index_command_counts.default = 0
    end

    stub_request(:post, url).with do |req|
      index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
      @index_command_counts[url] += index_cmds.size
    end
  end

  # ref. https://opensearch.org/docs/latest/opensearch/data-streams/
  class DataStreamNameTest < self

    def test_missing_data_stream_name
      conf = config_element(
        'ROOT', '', {
          '@type' => 'opensearch_datastream'
        })
      assert_raise Fluent::ConfigError.new("'data_stream_name' parameter is required") do
        driver(conf).run
      end
    end

    sub_test_case "invalid uppercase" do
      def test_stream_name
        conf = config_element(
          'ROOT', '', {
            '@type' => 'opensearch_datastream',
            'data_stream_name' => 'TEST',
            'data_stream_template_name' => 'template'
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must be lowercase only: <TEST>") do
          driver(conf)
        end
      end
      def test_stream_template_name
        conf = config_element(
          'ROOT', '', {
            '@type' => 'opensearch_datastream',
            'data_stream_name' => 'default',
            'data_stream_template_name' => 'TEST-TPL'
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must be lowercase only: <TEST-TPL>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid parameters" do
      data("backslash" => "\\",
           "slash" => "/",
           "asterisk" => "*",
           "question" => "?",
           "doublequote" => "\"",
           "lt" => "<",
           "gt" => ">",
           "bar" => "|",
           "space" => " ",
           "comma" => ",",
           "sharp" => "#",
           "colon" => ":")
      def test_stream_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "TEST#{c}",
            'data_stream_template_name' => "data_stream"
          })
        label = Fluent::Plugin::OpenSearchOutputDataStream::INVALID_CHARACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not contain invalid characters #{label}: <TEST#{c}>") do
          driver(conf)
        end
      end

      data("backslash" => "\\",
           "slash" => "/",
           "asterisk" => "*",
           "question" => "?",
           "doublequote" => "\"",
           "lt" => "<",
           "gt" => ">",
           "bar" => "|",
           "space" => " ",
           "comma" => ",",
           "sharp" => "#",
           "colon" => ":")
      def test_stream_template_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_template_name' => "TEST#{c}"
          })
        label = Fluent::Plugin::OpenSearchOutputDataStream::INVALID_CHARACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not contain invalid characters #{label}: <TEST#{c}>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid start characters" do
      data("hyphen" => "-",
           "underscore" => "_",
           "plus" => "+",
           "period" => ".")
      def test_stream_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}TEST",
            'data_stream_template_name' => "template"
          })
        label = Fluent::Plugin::OpenSearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not start with #{label}: <#{c}TEST>") do
          driver(conf)
        end
      end

      data("hyphen" => "-",
           "underscore" => "_",
           "plus" => "+",
           "period" => ".")
      def test_stream_template_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_template_name' => "#{c}TEST"
          })
        label = Fluent::Plugin::OpenSearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not start with #{label}: <#{c}TEST>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid dots" do
      data("current" => ".",
           "parents" => "..")
      def test_stream_name
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not be . or ..: <#{c}>") do
          driver(conf)
        end
      end

      data("current" => ".",
           "parents" => "..")
      def test_stream_template_name
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_template_name' => "#{c}"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not be . or ..: <#{c}>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid length" do
      def test_stream_name
        c = "a" * 256
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not be longer than 255 bytes: <#{c}>") do
          driver(conf)
        end
      end

      def test_stream_template_name
        c = "a" * 256
        conf = config_element(
          'ROOT', '', {
            '@type' => OPENSEARCH_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
           'data_stream_template_name' => "#{c}"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not be longer than 255 bytes: <#{c}>") do
          driver(conf)
        end
      end
    end
  end

  def test_datastream_configure
    stub_default
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_hosts_list_configure
    config = %{
      hosts            https://john:password@host1:443/elastic/,http://host2
      path             /default_path
      user             default_user
      password         default_password
      data_stream_name default
    }
    stub_opensearch_info("https://host1:443/elastic//", "1.2.2",
                         {'Authorization'=>"Basic #{Base64.encode64('john:password').split.first}"})
    stub_opensearch_info("http://host2/default_path/_data_stream/default", "1.2.2",
                         {'Authorization'=>"Basic #{Base64.encode64('john:password').split.first}"})
    stub_existent_data_stream?("default", "https://host1/elastic/")
    instance = driver(config).instance

    assert_equal 2, instance.get_connection_options[:hosts].length
    host1, host2 = instance.get_connection_options[:hosts]

    assert_equal 'host1', host1[:host]
    assert_equal 443, host1[:port]
    assert_equal 'https', host1[:scheme]
    assert_equal 'john', host1[:user]
    assert_equal 'password', host1[:password]
    assert_equal '/elastic/', host1[:path]

    assert_equal 'host2', host2[:host]
    assert_equal 'http', host2[:scheme]
    assert_equal 'default_user', host2[:user]
    assert_equal 'default_password', host2[:password]
    assert_equal '/default_path', host2[:path]
  end

  def test_datastream_configure_retry
    stub_opensearch_info
    stub_nonexistent_template_retry?
    stub_index_template
    stub_nonexistent_data_stream?
    stub_data_stream
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => "foo_tpl"
    })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_template_file
    stub_default
    cwd = File.dirname(__FILE__)
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => "foo_tpl",
      'template_file' => File.join(cwd, 'datastream_template.json')
    })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_existent_data_stream
    stub_index_template
    stub_existent_data_stream?
    stub_data_stream
    stub_opensearch_info
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_template_unset
    stub_index_template
    stub_existent_data_stream?
    stub_data_stream
    stub_opensearch_info
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
    assert_equal "foo_template", driver(conf).instance.data_stream_template_name
  end

  def test_placeholder
    dsname = "foo_test"
    tplname = "foo_tpl_test"
    stub_default(dsname, tplname)
    stub_bulk_feed(dsname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${tag}',
        'data_stream_template_name' => "foo_tpl_${tag}"
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_placeholder_with_capital_letters
    dsname = "foo_test.capital_letters"
    tplname = "foo_tpl_test.capital_letters"
    stub_default(dsname, tplname)
    stub_bulk_feed(dsname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${tag}',
        'data_stream_template_name' => "foo_tpl_${tag}"
      })
    driver(conf).run(default_tag: 'TEST.CAPITAL_LETTERS') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_placeholder_params_unset
    dsname = "foo_test"
    tplname = "foo_test_template"
    stub_default(dsname, tplname)
    stub_bulk_feed(dsname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${tag}',
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end


  def test_time_placeholder
    time = Time.now
    dsname = "foo_#{time.strftime("%Y%m%d")}"
    tplname = "foo_tpl_#{time.strftime("%Y%m%d")}"
    stub_default(dsname, tplname)
    stub_bulk_feed(dsname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_%Y%m%d',
        'data_stream_template_name' => 'foo_tpl_%Y%m%d'
      }, [config_element('buffer', 'time', {
                          'timekey' => '1d'
                        }, [])]
      )
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_custom_record_placeholder
    keys = ["bar", "baz"]
    keys.each do |key|
      dsname = "foo_#{key}"
      tplname = "foo_tpl_#{key}"
      stub_default(dsname, tplname)
      stub_bulk_feed(dsname, tplname)
    end
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${key1}',
        'data_stream_template_name' => 'foo_tpl_${key1}'
      }, [config_element('buffer', 'tag,key1', {
                          'timekey' => '1d'
                        }, [])]
    )
    driver(conf).run(default_tag: 'test') do
      keys.each do |key|
        record = sample_record.merge({"key1" => key})
        driver.feed(record)
      end
    end
    assert_equal keys.count, @bulk_records
  end

  def test_bulk_insert_feed
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
        '@type' => OPENSEARCH_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_template_name' => 'foo_tpl'
    })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_placeholder_writes_to_multi_hosts
    stub_default("foo_bar", "foo_tpl_bar")
    hosts = [['192.168.33.50', 9201], ['192.168.33.51', 9201], ['192.168.33.52', 9201]]
    hosts_string = hosts.map {|x| "#{x[0]}:#{x[1]}"}.compact.join(',')
    hosts.each do |host_info|
      host, port = host_info
      stub_opensearch_with_store_index_command_counts("http://#{host}:#{port}/foo_bar/_bulk")
      stub_opensearch_info("http://#{host}:#{port}/")
      stub_request(:get, "http://#{host}:#{port}/_data_stream/foo_bar").
        to_return(status: 200, body: "", headers: {})
    end

    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo_${key1}',
      'data_stream_template_name' => 'foo_tpl_${key1}',
      'hosts' => "#{hosts_string}"
    }, [config_element('buffer', 'tag,key1', {
      'timekey' => '1d'
    }, [])])
    driver(conf).run(default_tag: 'test') do
      hashes = {
        'age' => rand(100),
        'key1' => 'bar'
      }
      1000.times do
        driver.feed(sample_record.merge(hashes))
      end
    end

    # @note: we cannot make multi chunks with options (flush_interval, buffer_chunk_limit)
    # it's Fluentd test driver's constraint
    # so @index_command_counts.size is always 1
    assert(@index_command_counts.size > 0, "not working with hosts options")

    total = 0
    @index_command_counts.each do |_, count|
      total += count
    end
    assert_equal(2000, total)
  end

  def test_template_retry_install_fails
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_index_template.json')

    config = %{
      host                       logs.google.com
      port                       778
      scheme                     https
      data_stream_name           foo
      data_stream_template_name  foo_tpl
      user                       john
      password                   doe
      template_name              logstash
      template_file              #{template_file}
      max_retry_putting_template 3
    }

    connection_resets = 0
    # check if template exists
    stub_request(:get, "https://logs.google.com:778/_index_template/logstash")
      .with(basic_auth: ['john', 'doe']) do |req|
      connection_resets += 1
      raise Faraday::ConnectionFailed, "Test message"
    end
    stub_opensearch_info("https://logs.google.com:778/")

    assert_raise(Fluent::Plugin::OpenSearchError::RetryableOperationExhaustedFailure) do
      driver(config)
    end

    assert_equal(4, connection_resets)
  end

  def test_uses_custom_time_key
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl',
      'time_key' => 'vtm'
    })

    ts = DateTime.new(2021,2,3).iso8601(9)
    record = {
      'vtm' => ts,
      'message' => 'Sample Record'
    }

    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_with_format
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl',
      'time_key' => 'vtm',
      'time_key_format' => '%Y-%m-%d %H:%M:%S.%N%z'
    })
    ts = "2021-02-03 13:14:01.673+02:00"
    record = {
      'vtm' => ts,
      'message' => 'Sample Record'
    }
    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(DateTime.parse(ts).iso8601(9), index_cmds[1]['@timestamp'])
  end

  def test_record_no_timestamp
    stub_default
    stub_bulk_feed
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl'
    })
    record = {
      'message' => 'Sample Record'
    }
    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
  end

  def test_record_with_include_tag_key
    stub_default
    stub_bulk_feed
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl',
      'include_tag_key' => true,
      'tag_key' => 'test_tag'
    })
    record = {
      'message' => 'Sample Record'
    }
    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(index_cmds[1].has_key?('test_tag'))
  end

  def test_record_without_include_tag_key
    stub_default
    stub_bulk_feed
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl',
      'include_tag_key' => false
    })
    record = {
      'message' => 'Sample Record'
    }
    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(!index_cmds[1].has_key?('test'))
  end

  def test_record_with_remove_keys
    stub_default
    stub_bulk_feed
    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
      '@type' => OPENSEARCH_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_template_name' => 'foo_tpl',
      'remove_keys' => 'remove_me'
    })
    record = {
      'message' => 'Sample Record',
      'remove_me' => 'foo'
    }
    driver(conf).run(default_tag: 'test') do
      driver.feed(record)
    end
    assert(!index_cmds[1].has_key?('remove_me'))
  end

end
