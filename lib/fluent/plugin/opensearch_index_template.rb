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

require 'fluent/error'
require_relative './opensearch_error'

module Fluent::OpenSearchIndexTemplate
  def get_template(template_file)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'')
    JSON.parse(file_contents)
  end

  def get_custom_template(template_file, customize_template)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'')
    customize_template.each do |key, value|
      file_contents = file_contents.gsub(key,value.downcase)
    end
    JSON.parse(file_contents)
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

  def host_unreachable_exceptions
    client.transport.transport.host_unreachable_exceptions
  end

  def retry_operate(max_retries, fail_on_retry_exceed = true, catch_transport_exceptions = true)
    return unless block_given?
    retries = 0
    transport_errors = OpenSearch::Transport::Transport::Errors.constants.map{ |c| OpenSearch::Transport::Transport::Errors.const_get c } if catch_transport_exceptions
    begin
      yield
    rescue *host_unreachable_exceptions, *transport_errors, Timeout::Error => e
      @_es = nil
      @_es_info = nil
      if retries < max_retries
        retries += 1
        wait_seconds = 2**retries
        sleep wait_seconds
        log.warn "Could not communicate to OpenSearch, resetting connection and trying again. #{e.message}"
        log.warn "Remaining retry: #{max_retries - retries}. Retry to communicate after #{wait_seconds} second(s)."
        retry
      end
      message = "Could not communicate to OpenSearch after #{retries} retries. #{e.message}"
      log.warn message
      raise Fluent::Plugin::OpenSearchError::RetryableOperationExhaustedFailure,
            message if fail_on_retry_exceed
    end
  end

  def template_put(name, template, host = nil)
    if @use_legacy_template
      client(host).indices.put_template(:name => name, :body => template)
    else
      client(host).indices.put_index_template(:name => name, :body => template)
    end
  end

  def indexcreation(index_name, host = nil)
    client(host).indices.create(:index => index_name)
  rescue OpenSearch::Transport::Transport::Error => e
    if e.message =~ /"already exists"/ || e.message =~ /resource_already_exists_exception/
      log.debug("Index #{index_name} already exists")
    else
      log.error("Error while index creation - #{index_name}", error: e)
    end
  end

  def template_install(name, template_file, overwrite, host = nil, target_index = nil, index_separator = '-')
    if overwrite
      template_put(name,
                   get_template(template_file), host)

      log.debug("Template '#{name}' overwritten with #{template_file}.")
      return
    end
    if !template_exists?(name, host)
      template_put(name,
                   get_template(template_file), host)
      log.info("Template configured, but no template installed. Installed '#{name}' from #{template_file}.")
    else
      log.debug("Template '#{name}' configured and already installed.")
    end
  end

  def template_custom_install(template_name, template_file, overwrite, customize_template, host, target_index, index_separator)
    custom_template = get_custom_template(template_file, customize_template)

    if overwrite
      template_put(template_name, custom_template, host)
      log.info("Template '#{template_name}' overwritten with #{template_file}.")
    else
      if !template_exists?(template_name, host)
        template_put(template_name, custom_template, host)
        log.info("Template configured, but no template installed. Installed '#{template_name}' from #{template_file}.")
      else
        log.debug("Template '#{template_name}' configured and already installed.")
      end
    end
  end

  def templates_hash_install(templates, overwrite)
    templates.each do |key, value|
      template_install(key, value, overwrite)
    end
  end

  def rollover_alias_payload(rollover_alias)
    {
      'aliases' => {
        rollover_alias => {
          'is_write_index' =>  true
        }
      }
    }
  end
end
