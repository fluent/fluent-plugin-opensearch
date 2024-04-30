## Index

* [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
  + [host](#host)
  + [port](#port)
  + [hosts](#hosts)
  + [user, password, path, scheme, ssl_verify](#user-password-path-scheme-ssl_verify)
  + [parse_timestamp](#parse_timestamp)
  + [timestampkey_format](#timestampkey_format)
  + [timestamp_key](#timestamp_key)
  + [timestamp_parse_error_tag](#timestamp_parse_error_tag)
  + [http_backend](#http_backend)
  + [request_timeout](#request_timeout)
  + [reload_connections](#reload_connections)
  + [reload_on_failure](#reload_on_failure)
  + [resurrect_after](#resurrect_after)
  + [with_transporter_log](#with_transporter_log)
  + [emit_error_label_event](#emit-error-label-event)
  + [Client/host certificate options](#clienthost-certificate-options)
  + [sniffer_class_name](#sniffer-class-name)
  + [custom_headers](#custom_headers)
  + [docinfo_fields](#docinfo_fields)
  + [docinfo_target](#docinfo_target)
  + [docinfo](#docinfo)
  + [check_connection](#check_connection)
  + [retry_forever](#retry_forever)
  + [retry_timeout](#retry_timeout)
  + [retry_max_times](#retry_max_times)
  + [retry_type](#retry_type)
  + [retry_wait](#retry_wait)
  + [retry_exponential_backoff_base](#retry_exponential_backoff_base)
  + [retry_max_interval](#retry_max_interval)
  + [retry_randomize](#retry_randomize)

* [Advanced Usage](#advanced-usage)

## Usage

In your Fluentd configuration, use `@type opensearch` and specify `tag your.awesome.tag`. Additional configuration is optional, default values would look like this:

```
<source>
  @type opensearch
  host localhost
  port 9200
  index_name fluentd
  type_name fluentd
  tag my.logs
</source>
```

## Configuration

### host

```
host user-custom-host.domain # default localhost
```

You can specify OpenSearch host by this parameter.


### port

```
port 9201 # defaults to 9200
```

You can specify OpenSearch port by this parameter.

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

### parse_timestamp

```
parse_timestamp true # defaults to false
```

Parse a `@timestamp` field and add parsed time to the event.

### timestamp_key_format

The format of the time stamp field (`@timestamp` or what you specify in OpenSearch). This parameter only has an effect when [parse_timestamp](#parse_timestamp) is true as it only affects the name of the index we write to. Please see [Time#strftime](http://ruby-doc.org/core-1.9.3/Time.html#method-i-strftime) for information about the value of this format.

Setting this to a known format can vastly improve your log ingestion speed if all most of your logs are in the same format. If there is an error parsing this format the timestamp will default to the ingestion time. If you are on Ruby 2.0 or later you can get a further performance improvement by installing the "strptime" gem: `fluent-gem install strptime`.

For example to parse ISO8601 times with sub-second precision:

```
timestamp_key_format %Y-%m-%dT%H:%M:%S.%N%z
```

### timestamp_parse_error_tag

With `parse_timestamp true`, opensearch input plugin parses timestamp field for consuming event time. If the consumed record has invalid timestamp value, this plugin emits an error event to `@ERROR` label with `timestamp_parse_error_tag` configured tag.

Default value is `opensearch_plugin.input.time.error`.

### http_backend

With `http_backend typhoeus`, opensearch plugin uses typhoeus faraday http backend.
Typhoeus can handle HTTP keepalive.

Default value is `excon` which is default http_backend of opensearch plugin.

```
http_backend typhoeus
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

### with_transporter_log

This is debugging purpose option to enable to obtain transporter layer log.
Default value is `false` for backward compatibility.

We recommend to set this true if you start to debug this plugin.

```
with_transporter_log true
```

### emit_error_label_event

Default `emit_error_label_event` value is `true`.

Emitting error label events is default behavior.

When using the followin configuration, OpenSearch plugin will cut error events on error handler:

```aconf
emit_error_label_event false
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

### custom_headers

This parameter adds additional headers to request. The default value is `{}`.

```
custom_headers {"token":"secret"}
```

### docinfo_fields

This parameter specifies docinfo record keys. The default values are `['_index', '_type', '_id']`.

```
docinfo_fields ['_index', '_id']
```

### docinfo_target

This parameter specifies docinfo storing key. The default value is `@metadata`.

```
docinfo_target metadata
```

### docinfo

This parameter specifies whether docinfo information including or not. The default value is `false`.

```
docinfo false
```

### check_connection

The parameter for checking on connection availability with Elasticsearch or Opensearch hosts. The default value is `true`.

```
check_connection true
```
### retry_forever

The parameter If true, plugin will ignore retry_timeout and retry_max_times options and retry forever. The default value is `true`.

```
retry_forever true
```

### retry_timeout

The parameter maximum time (seconds) to retry again the failed try, until the plugin discards the retry.
If the next retry is going to exceed this time limit, the last retry will be made at exactly this time limit..
The default value is `72h`.
72hours == 17 times with exponential backoff (not to change default behavior)

```
retry_timeout 72 * 60 * 60
```

### retry_max_times

The parameter maximum number of times to retry the failed try. The default value is `5`

```
retry_max_times 5
```

### retry_type

The parameter needs for how long need to wait (time in seconds) to retry again:
`exponential_backoff`: wait in seconds will become large exponentially per failure,
`periodic`: plugin will retry periodically with fixed intervals (configured via retry_wait). The default value is `:exponential_backoff`
Periodic -> fixed :retry_wait
Exponential backoff: k is number of retry times
c: constant factor, @retry_wait
b: base factor, @retry_exponential_backoff_base
k: times
total retry time: c + c * b^1 + (...) + c*b^k = c*b^(k+1) - 1

```
retry_type exponential_backoff
```

### retry_wait

The parameter needs for wait in seconds before the next retry to again or constant factor of exponential backoff. The default value is  `5`

```
retry_wait 5
```

### retry_exponential_backoff_base

The parameter The base number of exponential backoff for retries. The default value is  `2`

```
retry_exponential_backoff_base 2
```

### retry_max_interval

The parameter maximum interval (seconds) for exponential backoff between retries while failing. The default value is  `nil`

```
retry_max_interval nil
```

### retry_randomize

The parameter If true, the plugin will retry after randomized interval not to do burst retries. The default value is  `false`

```
retry_randomize false
```

## Advanced Usage

OpenSearch Input plugin and OpenSearch output plugin can combine to transfer records into another cluster.

```aconf
<source>
  @type opensearch
  host original-cluster.local
  port 9200
  tag raw.opensearch
  index_name logstash-*
  docinfo true
  # repeat false
  # num_slices 2
  # with_transporter_log true
</source>
<match raw.opensearch>
  @type opensearch
  host transferred-cluster.local
  port 9200
  index_name ${$.@metadata._index}
  type_name ${$.@metadata._type} # This parameter will be deprecated due to Removal of mapping types since ES7.
  id_key ${$.@metadata._id} # This parameter is needed for prevent duplicated records.
  <buffer tag, $.@metadata._index, $.@metadata._type, $.@metadata._id>
    @type memory # should use file buffer for preventing chunk lost
  </buffer>
</match>
```
