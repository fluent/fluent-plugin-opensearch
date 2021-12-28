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

  def retry_operate(max_retries, fail_on_retry_exceed = true, catch_trasport_exceptions = true)
    return unless block_given?
    retries = 0
    transport_errors = OpenSearch::Transport::Transport::Errors.constants.map{ |c| OpenSearch::Transport::Transport::Errors.const_get c } if catch_trasport_exceptions
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

  def template_install(name, template_file, overwrite, deflector_alias_name = nil, host = nil, target_index = nil, index_separator = '-')
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

  def template_custom_install(template_name, template_file, overwrite, customize_template, deflector_alias_name, host, target_index, index_separator)
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

  def create_rollover_alias(target_index, rollover_index, deflector_alias_name, app_name, index_date_pattern, index_separator, host)
     # request to create alias.
    if rollover_index
      if !client.indices.exists_alias(:name => deflector_alias_name)
        if @logstash_format
          index_name_temp = '<'+target_index+'-000001>'
        else
          if index_date_pattern.empty?
            index_name_temp = '<'+target_index.downcase+index_separator+app_name.downcase+'-000001>'
          else
            index_name_temp = '<'+target_index.downcase+index_separator+app_name.downcase+'-{'+index_date_pattern+'}-000001>'
          end
        end
        indexcreation(index_name_temp, host)
        body = rollover_alias_payload(deflector_alias_name)
        client.indices.put_alias(:index => index_name_temp, :name => deflector_alias_name,
                                 :body => body)
        log.info("The alias '#{deflector_alias_name}' is created for the index '#{index_name_temp}'")
      else
        log.debug("The alias '#{deflector_alias_name}' is already present")
      end
    else
      log.debug("No index and alias creation action performed because rollover_index is set to: '#{rollover_index}'")
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
