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

require 'securerandom'
require 'base64'
require 'fluent/plugin/filter'

module Fluent::Plugin
  class OpenSearchGenidFilter < Filter
    Fluent::Plugin.register_filter('opensearch_genid', self)

    config_param :hash_id_key, :string, :default => '_hash'
    config_param :include_tag_in_seed, :bool, :default => false
    config_param :include_time_in_seed, :bool, :default => false
    config_param :use_record_as_seed, :bool, :default => false
    config_param :use_entire_record, :bool, :default => false
    config_param :record_keys, :array, :default => []
    config_param :separator, :string, :default => '_'
    config_param :hash_type, :enum, list: [:md5, :sha1, :sha256, :sha512], :default => :sha1

    def initialize
      super
    end

    def configure(conf)
      super

      if !@use_entire_record
        if @record_keys.empty? && @use_record_as_seed
          raise Fluent::ConfigError, "When using record as hash seed, users must specify `record_keys`."
        end
      end

      if @use_record_as_seed
        class << self
          alias_method :filter, :filter_seed_as_record
        end
      else
        class << self
          alias_method :filter, :filter_simple
        end
      end
    end

    def filter(tag, time, record)
      # for safety.
    end

    def filter_simple(tag, time, record)
      record[@hash_id_key] = Base64.strict_encode64(SecureRandom.uuid)
      record
    end

    def filter_seed_as_record(tag, time, record)
      seed = ""
      seed += tag + separator if @include_tag_in_seed
      seed += time.to_s + separator if @include_time_in_seed
      if @use_entire_record
        record.each {|k,v| seed += "|#{k}|#{v}"}
      else
        seed += record_keys.map {|k| record[k]}.join(separator)
      end
      record[@hash_id_key] = Base64.strict_encode64(encode_hash(@hash_type, seed))
      record
    end

    def encode_hash(type, seed)
      case type
      when :md5
        Digest::MD5.digest(seed)
      when :sha1
        Digest::SHA1.digest(seed)
      when :sha256
        Digest::SHA256.digest(seed)
      when :sha512
        Digest::SHA512.digest(seed)
      end
    end
  end
end
