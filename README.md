# Fluent::Plugin::OpenSearch, a plugin for [Fluentd](http://fluentd.org)

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-opensearch.png)](http://badge.fury.io/rb/fluent-plugin-opensearch)
![Testing on Windows](https://github.com/fluent/fluent-plugin-opensearch/workflows/Testing%20on%20Windows/badge.svg?branch=main)
![Testing on macOS](https://github.com/fluent/fluent-plugin-opensearch/workflows/Testing%20on%20macOS/badge.svg?branch=main)
![Testing on Ubuntu](https://github.com/fluent/fluent-plugin-opensearch/workflows/Testing%20on%20Ubuntu/badge.svg?branch=main)

Send your logs to OpenSearch (and search them with OpenSearch Dashboard maybe?)

* [Installation](#installation)
* [Usage](#usage)
  + [Index templates](#index-templates)
* [Configuration](#configuration)
  + [host](#host)
  + [port](#port)
  + [cloud_id](#cloud_id)
  + [cloud_auth](#cloud_auth)
  + [emit_error_for_missing_id](#emit_error_for_missing_id)
  + [hosts](#hosts)
  + [user, password, path, scheme, ssl_verify](#user-password-path-scheme-ssl_verify)
  + [logstash_format](#logstash_format)
  + [logstash_prefix](#logstash_prefix)
  + [logstash_prefix_separator](#logstash_prefix_separator)
  + [logstash_dateformat](#logstash_dateformat)
  + [pipeline](#pipeline)
  + [time_key_format](#time_key_format)
  + [time_precision](#time_precision)
  + [time_key](#time_key)
  + [time_key_exclude_timestamp](#time_key_exclude_timestamp)
  + [include_timestamp](#include_timestamp)
  + [utc_index](#utc_index)
  + [suppress_type_name](#suppress_type_name)
  + [target_index_key](#target_index_key)
  + [target_type_key](#target_type_key)
  + [target_index_affinity](#target_index_affinity)
  + [template_name](#template_name)
  + [template_file](#template_file)
  + [template_overwrite](#template_overwrite)
  + [customize_template](#customize_template)
  + [index_date_pattern](#index_date_pattern)
  + [application_name](#application_name)
  + [index_prefix](#index_prefix)
  + [templates](#templates)
  + [max_retry_putting_template](#max_retry_putting_template)
  + [fail_on_putting_template_retry_exceed](#fail_on_putting_template_retry_exceed)
  + [fail_on_detecting_os_version_retry_exceed](#fail_on_detecting_os_version_retry_exceed)
  + [max_retry_get_os_version](#max_retry_get_os_version)
  + [request_timeout](#request_timeout)
  + [reload_connections](#reload_connections)
  + [reload_on_failure](#reload_on_failure)
  + [resurrect_after](#resurrect_after)
  + [include_tag_key, tag_key](#include_tag_key-tag_key)
  + [id_key](#id_key)
  + [parent_key](#parent_key)
  + [routing_key](#routing_key)
  + [remove_keys](#remove_keys)
  + [remove_keys_on_update](#remove_keys_on_update)
  + [remove_keys_on_update_key](#remove_keys_on_update_key)
  + [retry_tag](#retry_tag)
  + [write_operation](#write_operation)
  + [time_parse_error_tag](#time_parse_error_tag)
  + [reconnect_on_error](#reconnect_on_error)
  + [with_transporter_log](#with_transporter_log)
  + [content_type](#content_type)
  + [include_index_in_url](#include_index_in_url)
  + [http_backend](#http_backend)
  + [http_backend_excon_nonblock](#http_backend_excon_nonblock)
  + [prefer_oj_serializer](#prefer_oj_serializer)
  + [compression_level](#compression_level)
  + [Client/host certificate options](#clienthost-certificate-options)
  + [Proxy Support](#proxy-support)
  + [Buffer options](#buffer-options)
  + [Hash flattening](#hash-flattening)
  + [Generate Hash ID](#generate-hash-id)
  + [sniffer_class_name](#sniffer-class-name)
  + [selector_class_name](#selector-class-name)
  + [reload_after](#reload-after)
  + [validate_client_version](#validate-client-version)
  + [unrecoverable_error_types](#unrecoverable-error-types)
  + [verify os version at startup](#verify_os_version_at_startup)
  + [default_opensearch_version](#default_opensearch_version)
  + [custom_headers](#custom_headers)
  + [api_key](#api_key)
  + [Not seeing a config you need?](#not-seeing-a-config-you-need)
  + [Dynamic configuration](#dynamic-configuration)
  + [Placeholders](#placeholders)
  + [Multi workers](#multi-workers)
  + [log_os_400_reason](#log_os_400_reason)
  + [suppress_doc_wrap](#suppress_doc_wrap)
  + [ignore_exceptions](#ignore_exceptions)
  + [exception_backup](#exception_backup)
  + [bulk_message_request_threshold](#bulk_message_request_threshold)
  + [truncate_caches_interval](#truncate_caches_interval)
  + [use_legacy_template](#use_legacy_template)
  + [metadata section](#metadata-section)
    + [include_chunk_id](#include_chunk_id)
    + [chunk_id_key](#chunk_id_key)
* [Configuration - OpenSearch Input](#configuration---opensearch-input)
* [Configuration - OpenSearch Filter GenID](#configuration---opensearch-filter-genid)
* [Configuration - OpenSearch Output Data Stream](#configuration---opensearch-output-data-stream)
* [OpenSearch permissions](#opensearch-permissions)
* [Troubleshooting](#troubleshooting)
* [Contact](#contact)
* [Contributing](#contributing)
* [Running tests](#running-tests)

## Requirements

| fluent-plugin-opensearch  | fluentd     | ruby   |
|:----------------------------:|:-----------:|:------:|
| >= 1.0.0                     | >= v1.x  | >= 2.4 |

NOTE: This documentation is for fluent-plugin-opensearch 1.x or later.

## Installation

```sh
$ gem install fluent-plugin-opensearch
```

## Usage

In your Fluentd configuration, use `@type opensearch`. Additional configuration is optional, default values would look like this:

```
<match my.logs>
  @type opensearch
  host localhost
  port 9200
  index_name fluentd
</match>
```

NOTE: `type_name` parameter is fixed value and cannot change and configure from `_doc` value for OpenSearch 1.

### Index templates

This plugin creates OpenSearch indices by merely writing to them. Consider using [Index Templates](https://opensearch.org/docs/latest/opensearch/index-templates/) to gain control of what get indexed and how.

## Configuration

### host

```
host user-custom-host.domain # default localhost
```

You can specify OpenSearch host by this parameter.

To use IPv6 address on `host` parameter, you can use the following styles:

#### string style

To use string style, you must quote IPv6 address due to prevent to be interpreted as JSON:

```
host "[2404:7a80:d440:3000:192a:a292:bd7f:ca10]"
```

#### raw style

You can also specify raw IPv6 address. This will be handled as `[specified IPv6 address]`:

```
host 2404:7a80:d440:3000:192a:a292:bd7f:ca10
```

### port

```
port 9201 # defaults to 9200
```

You can specify OpenSearch port by this parameter.

### emit_error_for_missing_id

```
emit_error_for_missing_id true
```
When  `write_operation` is configured to anything other then `index`, setting this value to `true` will
cause the plugin to `emit_error_event` of any records which do not include an `_id` field.  The default (`false`)
behavior is to silently drop the records.

### hosts

```
hosts host1:port1,host2:port2,host3:port3
```

You can specify multiple OpenSearch hosts with separator ",".

If you specify multiple hosts, this plugin will load balance updates to OpenSearch. This is an [opensearch-ruby](https://github.com/opensearch-project/opensearch-ruby) feature, the default strategy is round-robin.

If you specify `hosts` option, `host` and `port` options are ignored.

```
host user-custom-host.domain # ignored
port 9200                    # ignored
hosts host1:port1,host2:port2,host3:port3
```

If you specify `hosts` option without port, `port` option is used.

```
port 9200
hosts host1:port1,host2:port2,host3 # port3 is 9200
```

**Note:** If you will use scheme https, do not include "https://" in your hosts ie. host "https://domain", this will cause ES cluster to be unreachable and you will receive an error "Can not reach OpenSearch cluster"

**Note:** Embedded the username/password in the URL syntax is not recommended to use because it was found to cause serious connection problems. Please do not use its style on your settings and use the `user` and `password` field (described below) instead.

#### IPv6 addresses

When you want to specify IPv6 addresses, you must specify schema together:

```
hosts http://[2404:7a80:d440:3000:de:7311:6329:2e6c]:port1,http://[2404:7a80:d440:3000:de:7311:6329:1e6c]:port2,http://[2404:7a80:d440:3000:de:6311:6329:2e6c]:port3
```

If you don't specify hosts with schema together, OpenSearch plugin complains Invalid URI for them.

### user, password, path, scheme, ssl_verify

```
user demo
password secret
path /elastic_search/
scheme https
```

You can specify user and password for HTTP Basic authentication.

And this plugin will escape required URL encoded characters within `%{}` placeholders.

```
user %{demo+}
password %{@secret}
```

Specify `ssl_verify false` to skip ssl verification (defaults to true)

### logstash_format

```
logstash_format true # defaults to false
```

This is meant to make writing data into OpenSearch indices compatible to what [Logstash](https://www.elastic.co/products/logstash) calls them. By doing this, one could take advantage of [Kibana](https://www.elastic.co/products/kibana). See logstash\_prefix and logstash\_dateformat to customize this index name pattern. The index name will be `#{logstash_prefix}-#{formatted_date}`

:warning: Setting this option to `true` will ignore the `index_name` setting. The default index name prefix is `logstash-`.

### include_timestamp

```
include_timestamp true # defaults to false
```

Adds a `@timestamp` field to the log, following all settings `logstash_format` does, except without the restrictions on `index_name`. This allows one to log to an alias in OpenSearch and utilize the rollover API.

### logstash_prefix

```
logstash_prefix mylogs # defaults to "logstash"
```

### logstash_prefix_separator

```
logstash_prefix_separator _ # defaults to "-"
```

### logstash_dateformat

The strftime format to generate index target index name when `logstash_format` is set to true. By default, the records are inserted into index `logstash-YYYY.MM.DD`. This option, alongwith `logstash_prefix` lets us insert into specified index like `mylogs-YYYYMM` for a monthly index.

```
logstash_dateformat %Y.%m. # defaults to "%Y.%m.%d"
```

### pipeline

This param is to set a pipeline id of your opensearch to be added into the request, you can configure ingest node.
For more information: [![Ingest node](https://www.elastic.co/guide/en/opensearch/reference/master/ingest.html)]

```
pipeline pipeline_id
```

### time_key_format

The format of the time stamp field (`@timestamp` or what you specify with [time_key](#time_key)). This parameter only has an effect when [logstash_format](#logstash_format) is true as it only affects the name of the index we write to. Please see [Time#strftime](http://ruby-doc.org/core-1.9.3/Time.html#method-i-strftime) for information about the value of this format.

Setting this to a known format can vastly improve your log ingestion speed if all most of your logs are in the same format. If there is an error parsing this format the timestamp will default to the ingestion time. You can get a further performance improvement by installing the "strptime" gem: `fluent-gem install strptime`.

For example to parse ISO8601 times with sub-second precision:

```
time_key_format %Y-%m-%dT%H:%M:%S.%N%z
```

### time_precision

Should the record not include a `time_key`, define the degree of sub-second time precision to preserve from the `time` portion of the routed event.

For example, should your input plugin not include a `time_key` in the record but it able to pass a `time` to the router when emitting the event (AWS CloudWatch events are an example of this), then this setting will allow you to preserve the sub-second time resolution of those events. This is the case for: [fluent-plugin-cloudwatch-ingest](https://github.com/sampointer/fluent-plugin-cloudwatch-ingest).

### time_key

By default, when inserting records in [Logstash](https://www.elastic.co/products/logstash) format, `@timestamp` is dynamically created with the time at log ingestion. If you'd like to use a custom time, include an `@timestamp` with your record.

```
{"@timestamp": "2014-04-07T000:00:00-00:00"}
```

You can specify an option `time_key` (like the option described in [tail Input Plugin](http://docs.fluentd.org/articles/in_tail)) to replace `@timestamp` key.

Suppose you have settings

```
logstash_format true
time_key vtm
```

Your input is:
```
{
  "title": "developer",
  "vtm": "2014-12-19T08:01:03Z"
}
```

The output will be
```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
  "vtm": "2014-12-19T08:01:03Z"
}
```

See `time_key_exclude_timestamp` to avoid adding `@timestamp`.

### time_key_exclude_timestamp

```
time_key_exclude_timestamp false
```

By default, setting `time_key` will copy the value to an additional field `@timestamp`. When setting `time_key_exclude_timestamp true`, no additional field will be added.

### utc_index

```
utc_index true
```

By default, the records inserted into index `logstash-YYMMDD` with UTC (Coordinated Universal Time). This option allows to use local time if you describe utc_index to false.

### target_index_key

Tell this plugin to find the index name to write to in the record under this key in preference to other mechanisms. Key can be specified as path to nested record using dot ('.') as a separator.

If it is present in the record (and the value is non falsy) the value will be used as the index name to write to and then removed from the record before output; if it is not found then it will use logstash_format or index_name settings as configured.

Suppose you have the following settings

```
target_index_key @target_index
index_name fallback
```

If your input is:
```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
  "@target_index": "logstash-2014.12.19"
}
```

The output would be

```
{
  "title": "developer",
  "@timestamp": "2014-12-19T08:01:03Z",
}
```

and this record will be written to the specified index (`logstash-2014.12.19`) rather than `fallback`.

### target_type_key

Similar to `target_index_key` config, find the type name to write to in the record under this key (or nested record). If key not found in record - fallback to `type_name` (default "fluentd").

### target_index_affinity

Enable plugin to dynamically select logstash time based target index in update/upsert operations based on already indexed data rather than current time of indexing.

```
target_index_affinity true # defaults to false
```

By default plugin writes data of logstash format index based on current time. For example daily based index after mignight data is written to newly created index. This is normally ok when data is coming from single source and not updated after indexing.

But if you have a use case where data is also updated after indexing and `id_key` is used to identify the document uniquely for updating. Logstash format is wanted to be used for easy data managing and retention. Updates are done right after indexing to complete the data (all data not available from single source) and no updates are done anymore later point on time. In this case problem happends at index rotation time where write to 2 indexes with same id_key value may happen.

This setting will search existing data by using elastic search's [id query](https://www.elastic.co/guide/en/opensearch/reference/current/query-dsl-ids-query.html) using `id_key` value (with logstash_prefix and logstash_prefix_separator index pattarn e.g. `logstash-*`). The index of found data is used for update/upsert. When no data is found, data is written to current logstash index as normally.

This setting requires following other settings:
```
logstash_format true
id_key myId  # Some field on your data to identify the data uniquely
write_operation upsert  # upsert or update
```

Suppose you have the following situation where you have 2 different match to consume data from 2 different Kafka topics independently but close in time with each other (order not known).

```
  <match data1>
    @type opensearch
    ...
    id_key myId
    write_operation upsert
    logstash_format true
    logstash_dateformat %Y.%m.%d
    logstash_prefix myindexprefix
    target_index_affinity true
    ...

  <match data2>
    @type opensearch
    ...
    id_key myId
    write_operation upsert
    logstash_format true
    logstash_dateformat %Y.%m.%d
    logstash_prefix myindexprefix
    target_index_affinity true
    ...
```

If your first (data1) input is:
```
{
  "myId": "myuniqueId1",
  "datafield1": "some value",
}
```

and your second (data2) input is:
```
{
  "myId": "myuniqueId1",
  "datafield99": "some important data from other source tightly related to id myuniqueId1 and wanted to be in same document.",
}
```

Date today is 10.05.2021 so data is written to index `myindexprefix-2021.05.10` when both data1 and data2 is consumed during today.
But when we are close to index rotation and data1 is consumed and indexed at `2021-05-10T23:59:55.59707672Z` and data2
is consumed a bit later at `2021-05-11T00:00:58.222079Z` i.e. logstash index has been rotated and normally data2 would have been written
to index `myindexprefix-2021.05.11`. But with target_index_affinity setting as value true, data2 is now written to index `myindexprefix-2021.05.10`
into same document with data1 as wanted and duplicated document is avoided.

### template_name

The name of the template to define. If a template by the name given is already present, it will be left unchanged, unless [template_overwrite](#template_overwrite) is set, in which case the template will be updated.

This parameter along with template_file allow the plugin to behave similarly to Logstash (it installs a template at creation time) so that raw records are available. See [https://github.com/uken/fluent-plugin-elasticsearch/issues/33](https://github.com/uken/fluent-plugin-elasticsearch/issues/33).

[template_file](#template_file) must also be specified.

### template_file

The path to the file containing the template to install.

[template_name](#template_name) must also be specified.

### templates

Specify index templates in form of hash. Can contain multiple templates.

```
templates { "template_name_1": "path_to_template_1_file", "template_name_2": "path_to_template_2_file"}
```

**Note:** Before ES plugin v4.1.2, if `template_file` and `template_name` are set, then this parameter will be ignored. In 4.1.3 or later, `template_file` and `template_name` can work with `templates`.

### customize_template

Specify the string and its value to be replaced in form of hash. Can contain multiple key value pair that would be replaced in the specified template_file.

```
customize_template {"string_1": "subs_value_1", "string_2": "subs_value_2"}
```

If [template_file](#template_file) and [template_name](#template_name) are set, then this parameter will be in effect otherwise ignored.

### index_date_pattern

Specify this to override the index date pattern for creating a rollover index. The default is to use "now/d",
for example: <logstash-default-{now/d}-000001>. Overriding this changes the rollover time period. Setting
"now/w{xxxx.ww}" would create weekly rollover indexes instead of daily.

```
index_date_pattern "now/w{xxxx.ww}" # defaults to "now/d"
```

If empty string(`""`) is specified in `index_date_pattern`, index date pattern is not used.
OpenSearch plugin just creates <`target_index`-`application_name`-000001> rollover index instead of <`target_index`-`application_name`-`{index_date_pattern}`-000001>.

If [customize_template](#customize_template) is set, then this parameter will be in effect otherwise ignored.

### index_prefix

This parameter is marked as obsoleted.

### application_name

Specify the application name for the rollover index to be created.
```
application_name default # defaults to "default"
```

### template_overwrite

Always update the template, even if it already exists.

```
template_overwrite true # defaults to false
```

One of [template_file](#template_file) or [templates](#templates) must also be specified if this is set.

### max_retry_putting_template

You can specify times of retry putting template.

This is useful when OpenSearch plugin cannot connect OpenSearch to put template.
Usually, booting up clustered OpenSearch containers are much slower than launching Fluentd container.

```
max_retry_putting_template 15 # defaults to 10
```

### fail_on_putting_template_retry_exceed

Indicates whether to fail when `max_retry_putting_template` is exceeded.
If you have multiple output plugin, you could use this property to do not fail on fluentd statup.

```
fail_on_putting_template_retry_exceed false # defaults to true
```

### fail_on_detecting_os_version_retry_exceed

Indicates whether to fail when `max_retry_get_os_version` is exceeded.
If you want to use fallback mechanism for obtaining OpenSearch version, you could use this property to do not fail on fluentd statup.

```
fail_on_detecting_os_version_retry_exceed false
```

And the following parameters should be working with:

```
verify_os_version_at_startup true
max_retry_get_os_version 2 # greater than 0.
default_opensearch_version 1 # This version is used when occurring fallback.
```

### max_retry_get_os_version

You can specify times of retry obtaining OpenSearch version.

This is useful when OpenSearch plugin cannot connect OpenSearch to obtain OpenSearch version.
Usually, booting up clustered OpenSearch containers are much slower than launching Fluentd container.

```
max_retry_get_os_version 17 # defaults to 15
```

### request_timeout

You can specify HTTP request timeout.

This is useful when OpenSearch cannot return response for bulk request within the default of 5 seconds.

```
request_timeout 15s # defaults to 5s
```

### reload_connections

You can tune how the opensearch-transport host reloading feature works. By default it will reload the host list from the server every 10,000th request to spread the load. This can be an issue if your OpenSearch cluster is behind a Reverse Proxy, as Fluentd process may not have direct network access to the OpenSearch nodes.

```
reload_connections false # defaults to true
```

### reload_on_failure

Indicates that the opensearch-transport will try to reload the nodes addresses if there is a failure while making the
request, this can be useful to quickly remove a dead node from the list of addresses.

```
reload_on_failure true # defaults to false
```

### resurrect_after

You can set in the opensearch-transport how often dead connections from the opensearch-transport's pool will be resurrected.

```
resurrect_after 5s # defaults to 60s
```

### include_tag_key, tag_key

```
include_tag_key true # defaults to false
tag_key tag # defaults to tag
```

This will add the Fluentd tag in the JSON record. For instance, if you have a config like this:

```
<match my.logs>
  @type opensearch
  include_tag_key true
  tag_key _key
</match>
```

The record inserted into OpenSearch would be

```
{"_key": "my.logs", "name": "Johnny Doeie"}
```

### id_key

```
id_key request_id # use "request_id" field as a record id in ES
```

By default, all records inserted into OpenSearch get a random _id. This option allows to use a field in the record as an identifier.

This following record `{"name": "Johnny", "request_id": "87d89af7daffad6"}` will trigger the following OpenSearch command

```
{ "index" : { "_index": "logstash-2013.01.01", "_type": "fluentd", "_id": "87d89af7daffad6" } }
{ "name": "Johnny", "request_id": "87d89af7daffad6" }
```

Fluentd re-emits events that failed to be indexed/ingested in OpenSearch with a new and unique `_id` value, this means that congested OpenSearch clusters that reject events (due to command queue overflow, for example) will cause Fluentd to re-emit the event with a new `_id`, however OpenSearch may actually process both (or more) attempts (with some delay) and create duplicate events in the index (since each have a unique `_id` value), one possible workaround is to use the [fluent-plugin-genhashvalue](https://github.com/mtakemi/fluent-plugin-genhashvalue) plugin to generate a unique `_hash` key in the record of each event, this `_hash` record can be used as the `id_key` to prevent OpenSearch from creating duplicate events.

```
id_key _hash
```

Example configuration for [fluent-plugin-genhashvalue](https://github.com/mtakemi/fluent-plugin-genhashvalue) (review the documentation of the plugin for more details)
```
<filter logs.**>
  @type genhashvalue
  keys session_id,request_id
  hash_type md5    # md5/sha1/sha256/sha512
  base64_enc true
  base91_enc false
  set_key _hash
  separator _
  inc_time_as_key true
  inc_tag_as_key true
</filter>
```

:warning: In order to avoid hash-collisions and loosing data careful consideration is required when choosing the keys in the event record that should be used to calculate the hash

#### Using nested key

Nested key specifying syntax is also supported.

With the following configuration

```aconf
id_key $.nested.request_id
```

and the following nested record

```json
{"nested":{"name": "Johnny", "request_id": "87d89af7daffad6"}}
```

will trigger the following OpenSearch command

```
{"index":{"_index":"fluentd","_type":"fluentd","_id":"87d89af7daffad6"}}
{"nested":{"name":"Johnny","request_id":"87d89af7daffad6"}}
```

:warning: Note that [Hash flattening](#hash-flattening) may be conflict nested record feature.

### parent_key

```
parent_key a_parent # use "a_parent" field value to set _parent in opensearch command
```

If your input is
```
{ "name": "Johnny", "a_parent": "my_parent" }
```

OpenSearch command would be

```
{ "index" : { "_index": "****", "_type": "****", "_id": "****", "_parent": "my_parent" } }
{ "name": "Johnny", "a_parent": "my_parent" }
```

if `parent_key` is not configed or the `parent_key` is absent in input record, nothing will happen.

#### Using nested key

Nested key specifying syntax is also supported.

With the following configuration

```aconf
parent_key $.nested.a_parent
```

and the following nested record

```json
{"nested":{ "name": "Johnny", "a_parent": "my_parent" }}
```

will trigger the following OpenSearch command

```
{"index":{"_index":"fluentd","_type":"fluentd","_parent":"my_parent"}}
{"nested":{"name":"Johnny","a_parent":"my_parent"}}
```

:warning: Note that [Hash flattening](#hash-flattening) may be conflict nested record feature.

### routing_key

Similar to `parent_key` config, will add `_routing` into opensearch command if `routing_key` is set and the field does exist in input event.

### remove_keys

```
parent_key a_parent
routing_key a_routing
remove_keys a_parent, a_routing # a_parent and a_routing fields won't be sent to opensearch
```

### remove_keys_on_update

Remove keys on update will not update the configured keys in opensearch when a record is being updated.
This setting only has any effect if the write operation is update or upsert.

If the write setting is upsert then these keys are only removed if the record is being
updated, if the record does not exist (by id) then all of the keys are indexed.

```
remove_keys_on_update foo,bar
```

### remove_keys_on_update_key

This setting allows `remove_keys_on_update` to be configured with a key in each record, in much the same way as `target_index_key` works.
The configured key is removed before indexing in opensearch. If both `remove_keys_on_update` and `remove_keys_on_update_key` is
present in the record then the keys in record are used, if the `remove_keys_on_update_key` is not present then the value of
`remove_keys_on_update` is used as a fallback.

```
remove_keys_on_update_key keys_to_skip
```

### retry_tag

This setting allows custom routing of messages in response to bulk request failures.  The default behavior is to emit
failed records using the same tag that was provided.  When set to a value other then `nil`, failed messages are emitted
with the specified tag:

```
retry_tag 'retry_es'
```
**NOTE:** `retry_tag` is optional. If you would rather use labels to reroute retries, add a label (e.g '@label @SOMELABEL') to your fluent
opensearch plugin configuration. Retry records are, by default, submitted for retry to the ROOT label, which means
records will flow through your fluentd pipeline from the beginning.  This may nor may not be a problem if the pipeline
is idempotent - that is - you can process a record again with no changes.  Use tagging or labeling to ensure your retry
records are not processed again by your fluentd processing pipeline.

### write_operation

The write_operation can be any of:

| Operation | Description          |
| ------------- | ----------- |
| index (default)      | new data is added while existing data (based on its id) is replaced (reindexed).|
| create      | adds new data - if the data already exists (based on its id), the op is skipped.|
| update      | updates existing data (based on its id). If no data is found, the op is skipped.|
| upsert      | known as merge or insert if the data does not exist, updates if the data exists (based on its id).|

**Please note, id is required in create, update, and upsert scenario. Without id, the message will be dropped.**

### time_parse_error_tag

With `logstash_format true`, opensearch plugin parses timestamp field for generating index name. If the record has invalid timestamp value, this plugin emits an error event to `@ERROR` label with `time_parse_error_tag` configured tag.

Default value is `opensearch_plugin.output.time.error`. Note that this default values is quite different from Elasticsearch plugin.

### reconnect_on_error
Indicates that the plugin should reset connection on any error (reconnect on next send).
By default it will reconnect only on "host unreachable exceptions".
We recommended to set this true in the presence of opensearch shield.
```
reconnect_on_error true # defaults to false
```

### with_transporter_log

This is debugging purpose option to enable to obtain transporter layer log.
Default value is `false` for backward compatibility.

We recommend to set this true if you start to debug this plugin.

```
with_transporter_log true
```

### content_type

With `content_type application/x-ndjson`, opensearch plugin adds `application/x-ndjson` as `Content-Type` in payload.

Default value is `application/json` which is default Content-Type of OpenSearch requests.
If you will not use template, it recommends to set `content_type application/x-ndjson`.

```
content_type application/x-ndjson
```

### include_index_in_url

With this option set to true, Fluentd manifests the index name in the request URL (rather than in the request body).
You can use this option to enforce an URL-based access control.

```
include_index_in_url true
```

### http_backend

With `http_backend typhoeus`, opensearch plugin uses typhoeus faraday http backend.
Typhoeus can handle HTTP keepalive.

Default value is `excon` which is default http_backend of opensearch plugin.

```
http_backend typhoeus
```

### http_backend_excon_nonblock

With `http_backend_excon_nonblock false`, opensearch plugin use excon with nonblock=false.
If you use opensearch plugin with jRuby for https, you may need to consider to set `false` to avoid follwoing problems.
- https://github.com/geemus/excon/issues/106
- https://github.com/jruby/jruby-ossl/issues/19

But for all other case, it strongly reccomend to set `true` to avoid process hangin problem reported in https://github.com/uken/fluent-plugin-elasticsearch/issues/732

Default value is `true`.

```
http_backend_excon_nonblock false
```

### compression_level
You can add gzip compression of output data. In this case `default_compression`, `best_compression` or `best speed` option should be chosen.
By default there is no compression, default value for this option is `no_compression`
```
compression_level best_compression
```

### prefer_oj_serializer

With default behavior, OpenSearch client uses `Yajl` as JSON encoder/decoder.
`Oj` is the alternative high performance JSON encoder/decoder.
When this parameter sets as `true`, OpenSearch client uses `Oj` as JSON encoder/decoder.

Default value is `false`.

```
prefer_oj_serializer true
```

### Client/host certificate options

Need to verify OpenSearch's certificate?  You can use the following parameter to specify a CA instead of using an environment variable.
```
ca_file /path/to/your/ca/cert
```

Does your OpenSearch cluster want to verify client connections?  You can specify the following parameters to use your client certificate, key, and key password for your connection.
```
client_cert /path/to/your/client/cert
client_key /path/to/your/private/key
client_key_pass password
```

If you want to configure SSL/TLS version, you can specify ssl\_version parameter.
```
ssl_version TLSv1_2 # or [SSLv23, TLSv1, TLSv1_1]
```

:warning: If SSL/TLS enabled, it might have to be required to set ssl\_version.

In OpenSearch plugin v4.0.2 with Ruby 2.5 or later combination, OpenSearch plugin also support `ssl_max_version` and `ssl_min_version`.

```
ssl_max_version TLSv1_3
ssl_min_version TLSv1_2
```

OpenSearch plugin will use TLSv1.2 as minimum ssl version and TLSv1.3 as maximum ssl version on transportation with TLS. Note that when they are used in Elastissearch plugin configuration, *`ssl_version` is not used* to set up TLS version.

If they are *not* specified in the OpenSearch plugin configuration, `ssl_max_version` and `ssl_min_version` is set up with:

In OpenSearch plugin v1.0.0 or later with Ruby 2.5 or later environment, `ssl_max_version` should be `TLSv1_3` and `ssl_min_version` should be `TLSv1_2`.

### Proxy Support

Starting with version 0.8.0, this gem uses excon, which supports proxy with environment variables - https://github.com/excon/excon#proxy-support

### Buffer options

`fluentd-plugin-opensearch` extends [Fluentd's builtin Output plugin](https://docs.fluentd.org/output#overview) and use `compat_parameters` plugin helper. It adds the following options:

```
buffer_type memory
flush_interval 60s
retry_limit 17
retry_wait 1.0
num_threads 1
```

The value for option `buffer_chunk_limit` should not exceed value `http.max_content_length` in your OpenSearch setup (by default it is 100mb).

**Note**: If you use or evaluate Fluentd v0.14, you can use `<buffer>` directive to specify buffer configuration, too. In more detail, please refer to the [buffer configuration options for v0.14](https://docs.fluentd.org/v0.14/articles/buffer-plugin-overview#configuration-parameters)

**Note**: If you use `disable_retry_limit` in v0.12 or `retry_forever` in v0.14 or later, please be careful to consume memory inexhaustibly.

### Hash flattening

OpenSearch will complain if you send object and concrete values to the same field. For example, you might have logs that look this, from different places:

{"people" => 100}
{"people" => {"some" => "thing"}}

The second log line will be rejected by the OpenSearch parser because objects and concrete values can't live in the same field. To combat this, you can enable hash flattening.

```
flatten_hashes true
flatten_hashes_separator _
```

This will produce opensearch output that looks like this:
{"people_some" => "thing"}

Note that the flattener does not deal with arrays at this time.

### Generate Hash ID

By default, the fluentd opensearch plugin does not emit records with a \_id field, leaving it to OpenSearch to generate a unique \_id as the record is indexed. When an OpenSearch cluster is congested and begins to take longer to respond than the configured request_timeout, the fluentd opensearch plugin will re-send the same bulk request. Since OpenSearch can't tell its actually the same request, all documents in the request are indexed again resulting in duplicate data. In certain scenarios, this can result in essentially and infinite loop generating multiple copies of the same data.

The bundled opensearch\_genid filter can generate a unique \_hash key for each record, this key may be passed to the id_key parameter in the opensearch plugin to communicate to OpenSearch the uniqueness of the requests so that duplicates will be rejected or simply replace the existing records.
Here is a sample config:

```
<filter **>
  @type opensearch_genid
  hash_id_key _hash    # storing generated hash id key (default is _hash)
</filter>
<match **>
  @type opensearch
  id_key _hash # specify same key name which is specified in hash_id_key
  remove_keys _hash # OpenSearch doesn't like keys that start with _
  # other settings are omitted.
</match>
```

### Sniffer Class Name

The default Sniffer used by the `OpenSearch::Transport` class works well when Fluentd has a direct connection
to all of the OpenSearch servers and can make effective use of the `_nodes` API.  This doesn't work well
when Fluentd must connect through a load balancer or proxy.  The parameter `sniffer_class_name` gives you the
ability to provide your own Sniffer class to implement whatever connection reload logic you require.  In addition,
there is a new `Fluent::Plugin::OpenSearchSimpleSniffer` class which reuses the hosts given in the configuration, which
is typically the hostname of the load balancer or proxy.  For example, a configuration like this would cause
connections to `logging-es` to reload every 100 operations:

```
host logging-es
port 9200
reload_connections true
sniffer_class_name Fluent::Plugin::OpenSearchSimpleSniffer
reload_after 100
```

#### Tips

The included sniffer class is not required `out_opensearch`.
You should tell Fluentd where the sniffer class exists.

If you use td-agent, you must put the following lines into `TD_AGENT_DEFAULT` file:

```
sniffer=$(td-agent-gem contents fluent-plugin-opensearch|grep opensearch_simple_sniffer.rb)
TD_AGENT_OPTIONS="--use-v1-config -r $sniffer"
```

If you use Fluentd directly, you must pass the following lines as Fluentd command line option:

```
sniffer=$(td-agent-gem contents fluent-plugin-opensearch|grep opensearch_simple_sniffer.rb)
$ fluentd -r $sniffer [AND YOUR OTHER OPTIONS]
```

### Selector Class Name

The default selector used by the `OpenSearch::Transport` class works well when Fluentd should behave round robin and random selector cases. This doesn't work well when Fluentd should behave fallbacking from exhausted ES cluster to normal ES cluster.
The parameter `selector_class_name` gives you the ability to provide your own Selector class to implement whatever selection nodes logic you require.

The below configuration is using plugin built-in `ElasticseatchFallbackSelector`:

```
hosts exhausted-host:9201,normal-host:9200
selector_class_name "Fluent::Plugin::ElasticseatchFallbackSelector"
```

#### Tips

The included selector class is required in `out_opensearch` by default.
But, your custom selector class is not required in `out_opensearch`.
You should tell Fluentd where the selector class exists.

If you use td-agent, you must put the following lines into `TD_AGENT_DEFAULT` file:

```
selector=/path/to/your_awesome_selector.rb
TD_AGENT_OPTIONS="--use-v1-config -r $selector"
```

If you use Fluentd directly, you must pass the following lines as Fluentd command line option:

```
selector=/path/to/your_awesome_selector.rb
$ fluentd -r $selector [AND YOUR OTHER OPTIONS]
```

### Reload After

When `reload_connections true`, this is the integer number of operations after which the plugin will
reload the connections.  The default value is 10000.

### Validate Client Version

When you use mismatched OpenSearch server and client libraries, fluent-plugin-opensearch cannot send data into OpenSearch. The default value is `false`.

```
validate_client_version true
```

### Unrecoverable Error Types

Default `unrecoverable_error_types` parameter is set up strictly.
Because `rejected_execution_exception` is caused by exceeding OpenSearch's thread pool capacity.
Advanced users can increase its capacity, but normal users should follow default behavior.

If you want to increase it and forcibly retrying bulk request, please consider to change `unrecoverable_error_types` parameter from default value.

Change default value of `thread_pool.bulk.queue_size` in opensearch.yml:
e.g.)

```yaml
thread_pool.bulk.queue_size: 1000
```

Then, remove `rejected_execution_exception` from `unrecoverable_error_types` parameter:

```
unrecoverable_error_types ["out_of_memory_error"]
```

### verify_os_version_at_startup

Because OpenSearch plugin will ought to change behavior each of OpenSearch major versions.

For example, OpenSearch 1 requests to handle only `_doc` type_name in index.

If you want to disable to verify OpenSearch version at start up, set it as `false`.

When using the following configuration, OpenSearch plugin intends to communicate into OpenSearch 1.

```
verify_os_version_at_startup false
default_opensearch_version 1
```

The default value is `true`.

### default_opensearch_version

This parameter changes that OpenSearch plugin assumes the default OpenSearch version. The default value is `1`.

### custom_headers

This parameter adds additional headers to request. The default value is `{}`.

```
custom_headers {"token":"secret"}
```

### Not seeing a config you need?

We try to keep the scope of this plugin small and not add too many configuration options. If you think an option would be useful to others, feel free to open an issue or contribute a Pull Request.

Alternatively, consider using [fluent-plugin-forest](https://github.com/tagomoris/fluent-plugin-forest). For example, to configure multiple tags to be sent to different OpenSearch indices:

```
<match my.logs.*>
  @type forest
  subtype opensearch
  remove_prefix my.logs
  <template>
    logstash_prefix ${tag}
    # ...
  </template>
</match>
```

And yet another option is described in Dynamic Configuration section.

**Note**: If you use or evaluate Fluentd v0.14, you can use builtin placeholders. In more detail, please refer to [Placeholders](#placeholders) section.

### Placeholders

v0.14 placeholders can handle `${tag}` for tag, `%Y%m%d` like strftime format, and custom record keys like as `record["mykey"]`.

Note that custom chunk key is different notations for `record_reformer` and `record_modifier`.
They uses `record["some_key"]` to specify placeholders, but this feature uses `${key1}`, `${key2}` notation. And tag, time, and some arbitrary keys must be included in buffer directive attributes.

They are used as below:

#### tag

```aconf
<match my.logs>
  @type opensearch
  index_name elastic.${tag} #=> replaced with each event's tag. e.g.) elastic.test.tag
  <buffer tag>
    @type memory
  </buffer>
  # <snip>
</match>
```

#### time

```aconf
<match my.logs>
  @type opensearch
  index_name elastic.%Y%m%d #=> e.g.) elastic.20170811
  <buffer tag, time>
    @type memory
    timekey 3600
  </buffer>
  # <snip>
</match>
```

#### custom key

```log
records = {key1: "value1", key2: "value2"}
```

```aconf
<match my.logs>
  @type opensearch
  index_name elastic.${key1}.${key2} # => e.g.) elastic.value1.value2
  <buffer tag, key1, key2>
    @type memory
  </buffer>
  # <snip>
</match>
```

## Multi workers

Since Fluentd v0.14, multi workers feature had been implemented to increase throughput with multiple processes. This feature allows Fluentd processes to use one or more CPUs. This feature will be enabled by the following system configuration:

```
<system>
  workers N # where N is a natural number (N >= 1).
</system>
```

## log_os_400_reason

By default, the error logger won't record the reason for a 400 error from the OpenSearch API unless you set log_level to debug. However, this results in a lot of log spam, which isn't desirable if all you want is the 400 error reasons. You can set this `true` to capture the 400 error reasons without all the other debug logs.

Default value is `false`.

## suppress_doc_wrap

By default, record body is wrapped by 'doc'. This behavior can not handle update script requests. You can set this to suppress doc wrapping and allow record body to be untouched.

Default value is `false`.

## ignore_exceptions

A list of exception that will be ignored - when the exception occurs the chunk will be discarded and the buffer retry mechanism won't be called. It is possible also to specify classes at higher level in the hierarchy. For example

```
ignore_exceptions ["OpenSearch::Transport::Transport::ServerError"]
```

will match all subclasses of `ServerError` - `OpenSearch::Transport::Transport::Errors::BadRequest`, `OpenSearch::Transport::Transport::Errors::ServiceUnavailable`, etc.

Default value is empty list (no exception is ignored).

## exception_backup

Indicates whether to backup chunk when ignore exception occurs.

Default value is `true`.

## bulk_message_request_threshold

Configure `bulk_message` request splitting threshold size.

Default value is `-1`(unlimited).

If you specify this size as negative number, `bulk_message` request splitting feature will be disabled.

## truncate_caches_interval

Specify truncating caches interval.

If it is set, timer for clearing `alias_indexes` and `template_names` caches will be launched and executed.

Default value is `nil`.

## use_legacy_template

Use legacy template or not.

Composable template documentation is [Put Index Template API | OpenSearch Reference](https://opensearch.org/docs/latest/opensearch/index-templates/). OpenSearch still supports legacy template but we recommend to migrate to use Composable template.

Please confirm that whether the using OpenSearch cluster(s) support the composable template feature or not when turn on the brand new feature with this parameter.

## <metadata\> section

Users can specify whether including `chunk_id` information into records or not:

```aconf
<match your.awesome.routing.tag>
  @type opensearch
  # Other configurations.
  <metadata>
    include_chunk_id true
    # chunk_id_key chunk_id # Default value is "chunk_id".
  </metadata>
</match>
```

### include_chunk_id

Whether including `chunk_id` for not. Default value is `false`.

```aconf
<match your.awesome.routing.tag>
  @type opensearch
  # Other configurations.
  <metadata>
    include_chunk_id true
  </metadata>
</match>
```


### chunk_id_key

Specify `chunk_id_key` to store `chunk_id` information into records. Default value is `chunk_id`.

```aconf
<match your.awesome.routing.tag>
  @type opensearch
  # Other configurations.
  <metadata>
    include_chunk_id
    chunk_id_key chunk_hex
  </metadata>
</match>
```

## Configuration - OpenSearch Input

See [OpenSearch Input plugin document](README.OpenSearchInput.md)

## Configuration - OpenSearch Filter GenID

See [OpenSearch Filter GenID document](README.OpenSearchGenID.md)

## Configuration - OpenSearch Output Data Stream

Since Elasticsearch 7.9 that is predessor software of OpenSearch, Data Streams was introduced.

**NOTE:** This feature is slated to support. Currently, this fetaure is not supported yet.

You can enable this feature by specifying `@type opensearch_data_stream`.

```
@type opensearch_data_stream
data_stream_name test
```

When `@type opensearch_data_stream` is used, unless specified with `data_stream_ilm_name` and `data_stream_template_name`, ILM default policy is set to the specified data stream.
Then, the matching index template is also created automatically.

### data_stream_name

You can specify OpenSearch data stream name by this parameter.
This parameter is mandatory for `opensearch_data_stream`.

### data_stream_template_name

You can specify an existing matching index template for the data stream. If not present, it creates a new matching index template.

Default value is `data_stream_name`.

### data_stream_ilm_name

You can specify the name of an existing ILM policy, which will be applied to the data stream. If not present, it creates a new ILM default policy (unless `data_stream_template_name` is defined, in that case the ILM will be set to the one specified in the matching index template).

Default value is `data_stream_name`.

There are some limitations about naming rule.

In more detail, please refer to the [Path parameters](https://www.elastic.co/guide/en/opensearch/reference/master/indices-create-data-stream.html#indices-create-data-stream-api-path-params).

## Troubleshooting

See [Troubleshooting document](README.Troubleshooting.md)

## Contact

If you have a question, [open an Issue](https://github.com/fluent/fluent-plugin-opensearch/issues).

## Contributing

There are usually a few feature requests, tagged [Easy](https://github.com/fluent/fluent-plugin-opensearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3AEasy), [Normal](https://github.com/fluent/fluent-plugin-opensearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3ANormal) and [Hard](https://github.com/fluent/fluent-plugin-opensearch/issues?q=is%3Aissue+is%3Aopen+label%3Alevel%3AHard). Feel free to work on any one of them.

Pull Requests are welcomed.

Becore send a pull request or report an issue, please read [the contribution guideline](CONTRIBUTING.md).

## Running tests

Install dev dependencies:

```sh
$ gem install bundler
$ bundle install
$ bundle exec rake test
# To just run the test you are working on:
$ bundle exec rake test TEST=test/plugin/test_out_opensearch.rb TESTOPTS='--verbose --name=test_bulk_error_retags_with_error_when_configured_and_fullfilled_buffer'

```
