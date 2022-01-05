# SPDX-License-Identifier: Apache-2.0
#
# The fluent-plugin-opensearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
# Licensed toUken Inc. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
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
