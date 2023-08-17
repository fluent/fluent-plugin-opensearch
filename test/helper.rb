# coding: utf-8
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

require 'simplecov'
require 'simplecov'
require 'simplecov-lcov'

SimpleCov::Formatter::LcovFormatter.config do |config|
  config.report_with_single_file = true
  config.single_report_path = 'coverage/lcov.info'
end

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter.new([
  SimpleCov::Formatter::HTMLFormatter,
  SimpleCov::Formatter::LcovFormatter
])

SimpleCov.start do
  add_filter do |src|
    !(src.filename =~ /^#{SimpleCov.root}\/lib/)
  end
end

# needs to be after simplecov but before test/unit, because fluentd sets default
# encoding to ASCII-8BIT, but coverall might load git data which could contain a
# UTF-8 character
at_exit do
  Encoding.default_internal = 'UTF-8' if defined?(Encoding) && Encoding.respond_to?(:default_internal)
  Encoding.default_external = 'UTF-8' if defined?(Encoding) && Encoding.respond_to?(:default_external)
end

require 'test/unit'
require 'fluent/test'

require 'webmock/test_unit'
WebMock.disable_net_connect!
