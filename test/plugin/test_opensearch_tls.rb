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

require_relative '../helper'
require 'fluent/test/driver/output'
require 'fluent/plugin/output'
require 'fluent/plugin/opensearch_tls'

class TestOpenSearchTLS < Test::Unit::TestCase

  class TestTLSModuleOutput < Fluent::Plugin::Output
    include Fluent::Plugin::OpenSearchTLS

    def initialize
      super
      @emit_streams = []
    end

    def write(chunk)
      es = Fluent::ArrayEventStream.new
      chunk.each do |time, record|
        es.add(time, record)
      end
      @emit_streams << [tag, es]
    end
  end

  setup do
    Fluent::Test.setup
    @use_tls_minmax_version = begin
                                map = {
                                  TLSv1: OpenSSL::SSL::TLS1_VERSION,
                                  TLSv1_1: OpenSSL::SSL::TLS1_1_VERSION,
                                  TLSv1_2: OpenSSL::SSL::TLS1_2_VERSION
                                }
                                map[:TLSv1_3] = OpenSSL::SSL::TLS1_3_VERSION if defined?(OpenSSL::SSL::TLS1_3_VERSION)
                                true
                              rescue NameError
                                false
                              end
    @enabled_tlsv1_3 = begin
                         map = {TLSv1_3: OpenSSL::SSL::TLS1_3_VERSION}
                         true
                       rescue NameError
                         false
                       end
  end

  def driver(conf='')
    Fluent::Test::Driver::Output.new(TestTLSModuleOutput).configure(conf)
  end

  test 'configure' do
    assert_equal Fluent::Plugin::OpenSearchTLS::DEFAULT_VERSION, driver.instance.ssl_version
    assert_nil driver.instance.ssl_max_version
    assert_nil driver.instance.ssl_min_version
  end

  test 'check USE_TLS_MINMAX_VERSION value' do
    assert_equal @use_tls_minmax_version, Fluent::Plugin::OpenSearchTLS::USE_TLS_MINMAX_VERSION
  end

  sub_test_case 'set_tls_minmax_version_config' do
    test 'default' do
      d = driver('')
      ssl_version_options = d.instance.set_tls_minmax_version_config(d.instance.ssl_version, nil, nil)
      if @use_tls_minmax_version
        if @enabled_tlsv1_3
          assert_equal({max_version: OpenSSL::SSL::TLS1_3_VERSION,
                        min_version: OpenSSL::SSL::TLS1_2_VERSION}, ssl_version_options)
        else
          assert_equal({max_version: nil,
                        min_version: OpenSSL::SSL::TLS1_2_VERSION}, ssl_version_options)

        end
      else
        assert_equal({version: Fluent::Plugin::OpenSearchTLS::DEFAULT_VERSION}, ssl_version_options)
      end
    end

    test 'errorous cases' do
      if @use_tls_minmax_version
        assert_raise(Fluent::ConfigError) do
          d = driver(%{ssl_max_version TLSv1_2})
          d.instance.set_tls_minmax_version_config(d.instance.ssl_version,
                                                   d.instance.ssl_max_version,
                                                   d.instance.ssl_min_version)
        end
        assert_raise(Fluent::ConfigError) do
          d = driver(%{ssl_min_version TLSv1_2})
          d.instance.set_tls_minmax_version_config(d.instance.ssl_version,
                                                   d.instance.ssl_max_version,
                                                   d.instance.ssl_min_version)
        end
      else
        d1 = driver(%{
          ssl_max_version TLSv1_2
          @log_level info
        })
        d1.instance.set_tls_minmax_version_config(d1.instance.ssl_version,
                                                  d1.instance.ssl_max_version,
                                                  d1.instance.ssl_min_version)

        d1.logs.any? {|a| a.include?("'ssl_max_version' does not have any effect in this environment.") }
        d2 = driver(%{
          ssl_min_version TLSv1_2
          @log_level info
        })
        d2.instance.set_tls_minmax_version_config(d2.instance.ssl_version,
                                                  d2.instance.ssl_max_version,
                                                  d2.instance.ssl_min_version)
        d2.logs.any? {|a| a.include?("'ssl_min_version' does not have any effect in this environment.") }
      end
    end

    test 'min_version & max_version' do
      config = %{
        ssl_max_version TLSv1_2
        ssl_min_version TLSv1_1
      }
      d = driver(config)
      ssl_version_options = d.instance.set_tls_minmax_version_config(d.instance.ssl_version,
                                                                     d.instance.ssl_max_version,
                                                                     d.instance.ssl_min_version)
      if @use_tls_minmax_version
        assert_equal({max_version: OpenSSL::SSL::TLS1_2_VERSION,
                      min_version: OpenSSL::SSL::TLS1_1_VERSION}, ssl_version_options)
      else
        assert_equal({version: Fluent::Plugin::OpenSearchTLS::DEFAULT_VERSION}, ssl_version_options)
      end
    end

    test 'TLSv1.3' do
      omit "openssl gem does not support TLSv1.3" unless @enabled_tlsv1_3
      config = %{
        ssl_max_version TLSv1_3
        ssl_min_version TLSv1_2
      }
      d = driver(config)
      ssl_version_options = d.instance.set_tls_minmax_version_config(d.instance.ssl_version,
                                                                     d.instance.ssl_max_version,
                                                                     d.instance.ssl_min_version)
      assert_equal({max_version: OpenSSL::SSL::TLS1_3_VERSION,
                    min_version: OpenSSL::SSL::TLS1_2_VERSION}, ssl_version_options)

    end
  end
end
