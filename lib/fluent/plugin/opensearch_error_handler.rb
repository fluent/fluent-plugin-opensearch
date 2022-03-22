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

require 'fluent/event'
require 'fluent/error'
require_relative 'opensearch_constants'

class Fluent::Plugin::OpenSearchErrorHandler
  include Fluent::Plugin::OpenSearchConstants

  attr_accessor :bulk_message_count
  class OpenSearchVersionMismatch < Fluent::UnrecoverableError; end
  class OpenSearchSubmitMismatch < Fluent::UnrecoverableError; end
  class OpenSearchRequestAbortError < Fluent::UnrecoverableError; end
  class OpenSearchError < StandardError; end

  def initialize(plugin)
    @plugin = plugin
  end

  def unrecoverable_error_types
    @plugin.unrecoverable_error_types
  end

  def unrecoverable_error?(type)
    unrecoverable_error_types.include?(type)
  end

  def unrecoverable_record_error?(type)
    ['json_parse_exception'].include?(type)
  end

  def log_os_400_reason(&block)
    if @plugin.log_os_400_reason
      block.call
    else
      @plugin.log.on_debug(&block)
    end
  end

  def emit_error_label_event(&block)
    # If `emit_error_label_event` is specified as false, error event emittions are not occurred.
    if @plugin.emit_error_label_event
      block.call
    end
  end

  def handle_error(response, tag, chunk, bulk_message_count, extracted_values)
    items = response['items']
    if items.nil? || !items.is_a?(Array)
      raise OpenSearchVersionMismatch, "The response format was unrecognized: #{response}"
    end
    if bulk_message_count != items.length
      raise OpenSearchSubmitMismatch, "The number of records submitted #{bulk_message_count} do not match the number returned #{items.length}. Unable to process bulk response."
    end
    retry_stream = Fluent::MultiEventStream.new
    stats = Hash.new(0)
    meta = {}
    header = {}
    affinity_target_indices = @plugin.get_affinity_target_indices(chunk)
    chunk.msgpack_each do |time, rawrecord|
      bulk_message = ''
      next unless rawrecord.is_a? Hash
      begin
        # we need a deep copy for process_message to alter
        processrecord = Marshal.load(Marshal.dump(rawrecord))
        meta, header, record = @plugin.process_message(tag, meta, header, time, processrecord, affinity_target_indices, extracted_values)
        next unless @plugin.append_record_to_messages(@plugin.write_operation, meta, header, record, bulk_message)
      rescue => e
        @plugin.log.debug("Exception in error handler during deep copy: #{e}")
        stats[:bad_chunk_record] += 1
        next
      end
      item = items.shift
      if item.is_a?(Hash) && item.has_key?(@plugin.write_operation)
        write_operation = @plugin.write_operation
      elsif INDEX_OP == @plugin.write_operation && item.is_a?(Hash) && item.has_key?(CREATE_OP)
        write_operation = CREATE_OP
      elsif UPSERT_OP == @plugin.write_operation && item.is_a?(Hash) && item.has_key?(UPDATE_OP)
        write_operation = UPDATE_OP
      elsif item.nil?
        stats[:errors_nil_resp] += 1
        next
      else
        # When we don't have an expected ops field, something changed in the API
        # expected return values.
        stats[:errors_bad_resp] += 1
        next
      end
      if item[write_operation].has_key?('status')
        status = item[write_operation]['status']
      else
        # When we don't have a status field, something changed in the API
        # expected return values.
        stats[:errors_bad_resp] += 1
        next
      end
      case
      when [200, 201].include?(status)
        stats[:successes] += 1
      when CREATE_OP == write_operation && 409 == status
        stats[:duplicates] += 1
      when 400 == status
        stats[:bad_argument] += 1
        reason = ""
        log_os_400_reason do
          if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
            reason = " [error type]: #{item[write_operation]['error']['type']}"
          end
          if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('reason')
            reason += " [reason]: \'#{item[write_operation]['error']['reason']}\'"
          end
        end
        emit_error_label_event do
          @plugin.router.emit_error_event(tag, time, rawrecord, OpenSearchError.new("400 - Rejected by OpenSearch#{reason}"))
        end
      else
        if item[write_operation]['error'].is_a?(String)
          reason = item[write_operation]['error']
          stats[:errors_block_resp] += 1
          emit_error_label_event do
            @plugin.router.emit_error_event(tag, time, rawrecord, OpenSearchError.new("#{status} - #{reason}"))
          end
          next
        elsif item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
          type = item[write_operation]['error']['type']
          stats[type] += 1
          if unrecoverable_error?(type)
            raise OpenSearchRequestAbortError, "Rejected OpenSearch due to #{type}"
          end
          if unrecoverable_record_error?(type)
            emit_error_label_event do
              @plugin.router.emit_error_event(tag, time, rawrecord, OpenSearchError.new("#{status} - #{type}: #{reason}"))
            end
            next
          else
            retry_stream.add(time, rawrecord) unless unrecoverable_record_error?(type)
          end
        else
          # When we don't have a type field, something changed in the API
          # expected return values.
          stats[:errors_bad_resp] += 1
          emit_error_label_event do
            @plugin.router.emit_error_event(tag, time, rawrecord, OpenSearchError.new("#{status} - No error type provided in the response"))
          end
          next
        end
        stats[type] += 1
      end
    end
    @plugin.log.on_debug do
      msg = ["Indexed (op = #{@plugin.write_operation})"]
      stats.each_pair { |key, value| msg << "#{value} #{key}" }
      @plugin.log.debug msg.join(', ')
    end
    raise Fluent::Plugin::OpenSearchOutput::RetryStreamError.new(retry_stream) unless retry_stream.empty?
  end
end
