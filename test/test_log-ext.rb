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

require 'helper'
require 'fluent/log-ext'

class TestFluentLogExtHandler < Test::Unit::TestCase
  def setup
    @log_device = Fluent::Test::DummyLogDevice.new
    dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
    logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
    @log = Fluent::Log.new(logger)
  end

  def test_trace?
    assert_false @log.respond_to?(:trace?)
  end

  def test_debug?
    assert_true @log.respond_to?(:debug?)
  end

  def test_info?
    assert_true @log.respond_to?(:info?)
  end

  def test_warn?
    assert_true @log.respond_to?(:warn?)
  end

  def test_error?
    assert_true @log.respond_to?(:error?)
  end

  def test_fatal?
    assert_true @log.respond_to?(:fatal?)
  end
end
