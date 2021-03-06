## Index

* [Troubleshooting](#troubleshooting)
  + [Cannot send events to opensearch](#cannot-send-events-to-opensearch)
  + [Cannot see detailed failure log](#cannot-see-detailed-failure-log)
  + [Cannot connect TLS enabled reverse Proxy](#cannot-connect-tls-enabled-reverse-proxy)
  + [Declined logs are resubmitted forever, why?](#declined-logs-are-resubmitted-forever-why)
  + [Suggested to install typhoeus gem, why?](#suggested-to-install-typhoeus-gem-why)
  + [Random 400 - Rejected by OpenSearch is occured, why?](#random-400---rejected-by-opensearch-is-occured-why)
  + [Fluentd seems to hang if it unable to connect OpenSearch, why?](#fluentd-seems-to-hang-if-it-unable-to-connect-opensearch-why)
  + [How to specify index codec](#how-to-specify-index-codec)
  + [Cannot push logs to OpenSearch with connect_write timeout reached, why?](#cannot-push-logs-to-opensearch-with-connect_write-timeout-reached-why)
  + [Index State Management feature is not provided, why?](#index-state-management-feature-is-not-provided-why)


## Troubleshooting

### Cannot send events to OpenSearch

A common cause of failure is that you are trying to connect to an OpenSearch instance with an incompatible version.

You can check the actual version of the client library installed on your system by executing the following command.

```
# For td-agent users
$ /usr/sbin/td-agent-gem list opensearch
# For standalone Fluentd users
$ fluent-gem list opensearch
```
Or, fluent-plugin-opensearch v0.1.0 or later, users can inspect version incompatibility with the `validate_client_version` option:

```
validate_client_version true
```

If you get the following error message, please consider to install compatible opensearch client gems:

```
Detected OpenSearch 1 but you use OpenSearch client 2.0.0.
Please consider to use 1.x series OpenSearch client.
```

### Cannot see detailed failure log

A common cause of failure is that you are trying to connect to an OpenSearch instance with an incompatible ssl protocol version.

For example, `out_opensearch` set up ssl_version to TLSv1 due to historical reason.
Modern OpenSearch ecosystem requests to communicate with TLS v1.2 or later.
But, in this case, `out_opensearch` conceals transporter part failure log by default.
If you want to acquire transporter log, please consider to set the following configuration:

```
with_transporter_log true
@log_level debug
```

Then, the following log is shown in Fluentd log:

```
2018-10-24 10:00:00 +0900 [error]: #0 [Faraday::ConnectionFailed] SSL_connect returned=1 errno=0 state=SSLv2/v3 read server hello A: unknown protocol (OpenSSL::SSL::SSLError) {:host=>"opensearch-host", :port=>80, :scheme=>"https", :user=>"elastic", :password=>"changeme", :protocol=>"https"}
```

This indicates that inappropriate TLS protocol version is used.
If you want to use TLS v1.2, please use `ssl_version` parameter like as:

```
ssl_version TLSv1_2
```

or, in v4.0.2 or later with Ruby 2.5 or later combination, the following congiuration is also valid:

```
ssl_max_version TLSv1_2
ssl_min_version TLSv1_2
```

### Cannot connect TLS enabled reverse Proxy

A common cause of failure is that you are trying to connect to an OpenSearch instance behind nginx reverse proxy which uses an incompatible ssl protocol version.

For example, `out_opensearch` set up ssl_version to TLSv1 due to historical reason.
Nowadays, nginx reverse proxy uses TLS v1.2 or later for security reason.
But, in this case, `out_opensearch` conceals transporter part failure log by default.

If you set up nginx reverse proxy with TLS v1.2:

```
server {
    listen <your IP address>:9400;
    server_name <ES-Host>;
    ssl on;
    ssl_certificate /etc/ssl/certs/server-bundle.pem;
    ssl_certificate_key /etc/ssl/private/server-key.pem;
    ssl_client_certificate /etc/ssl/certs/ca.pem;
    ssl_verify_client   on;
    ssl_verify_depth    2;

    # Reference : https://cipherli.st/
    ssl_protocols TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off; # Requires nginx >= 1.5.9
    ssl_stapling on; # Requires nginx >= 1.3.7
    ssl_stapling_verify on; # Requires nginx => 1.3.7
    resolver 127.0.0.1 valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    client_max_body_size 64M;
    keepalive_timeout 5;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_pass http://localhost:9200;
    }
}
```

Then, nginx reverse proxy starts with TLSv1.2.

Fluentd suddenly dies with the following log:
```
Oct 31 9:44:45 <ES-Host> fluentd[6442]: log writing failed. execution expired
Oct 31 9:44:45 <ES-Host> fluentd[6442]: /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/ssl_socket.rb:10:in `initialize': stack level too deep (SystemStackError)
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:429:in `new'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:429:in `socket'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/connection.rb:111:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/mock.rb:48:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/instrumentor.rb:26:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/excon-0.62.0/lib/excon/middlewares/base.rb:16:in `request_call'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:          ... 9266 levels...
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/td-agent/embedded/lib/ruby/site_ruby/2.4.0/rubygems/core_ext/kernel_require.rb:55:in `require'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/lib/ruby/gems/2.4.0/gems/fluentd-1.2.5/bin/fluentd:8:in `<top (required)>'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/bin/fluentd:22:in `load'
Oct 31 9:44:45 <ES-Host> fluentd[6442]:         from /opt/fluentd/embedded/bin/fluentd:22:in `<main>'
Oct 31 9:44:45 <ES-Host> systemd[1]: fluentd.service: Control process exited, code=exited status=1
```

If you want to acquire transporter log, please consider to set the following configuration:

```
with_transporter_log true
@log_level debug
```

Then, the following log is shown in Fluentd log:

```
2018-10-31 10:00:57 +0900 [warn]: #7 [Faraday::ConnectionFailed] Attempt 2 connecting to {:host=>"<ES-Host>", :port=>9400, :scheme=>"https", :protocol=>"https"}
2018-10-31 10:00:57 +0900 [error]: #7 [Faraday::ConnectionFailed] Connection reset by peer - SSL_connect (Errno::ECONNRESET) {:host=>"<ES-Host>", :port=>9400, :scheme=>"https", :protocol=>"https"}
```

The above logs indicates that using incompatible SSL/TLS version between fluent-plugin-opensearch and nginx, which is reverse proxy, is root cause of this issue.

If you want to use TLS v1.2, please use `ssl_version` parameter like as:

```
ssl_version TLSv1_2
```

or, in v4.0.2 or later with Ruby 2.5 or later combination, the following congiuration is also valid:

```
ssl_max_version TLSv1_2
ssl_min_version TLSv1_2
```

### Declined logs are resubmitted forever, why?

Sometimes users write Fluentd configuration like this:

```aconf
<match **>
  @type opensearch
  host localhost
  port 9200
  type_name fluentd
  logstash_format true
  time_key @timestamp
  include_timestamp true
  reconnect_on_error true
  reload_on_failure true
  reload_connections false
  request_timeout 120s
</match>
```

The above configuration does not use [`@label` feature](https://docs.fluentd.org/v1.0/articles/config-file#(5)-group-filter-and-output:-the-%E2%80%9Clabel%E2%80%9D-directive) and use glob(**) pattern.
It is usually problematic configuration.

In error scenario, error events will be emitted with `@ERROR` label, and `fluent.*` tag.
The black hole glob pattern resubmits a problematic event into pushing OpenSearch pipeline.

This situation causes flood of declined log:

```log
2018-11-13 11:16:27 +0000 [warn]: #0 dump an error event: error_class=Fluent::Plugin::OpenSearchErrorHandler::OpenSearchError error="400 - Rejected by OpenSearch" location=nil tag="app.fluentcat" time=2018-11-13 11:16:17.492985640 +0000 record={"message"=>"\xFF\xAD"}
2018-11-13 11:16:38 +0000 [warn]: #0 dump an error event: error_class=Fluent::Plugin::OpenSearchErrorHandler::OpenSearchError error="400 - Rejected by OpenSearch" location=nil tag="fluent.warn" time=2018-11-13 11:16:27.978851140 +0000 record={"error"=>"#<Fluent::Plugin::OpenSearchErrorHandler::OpenSearchError: 400 - Rejected by OpenSearch>", "location"=>nil, "tag"=>"app.fluentcat", "time"=>2018-11-13 11:16:17.492985640 +0000, "record"=>{"message"=>"\xFF\xAD"}, "message"=>"dump an error event: error_class=Fluent::Plugin::OpenSearchErrorHandler::OpenSearchError error=\"400 - Rejected by OpenSearch\" location=nil tag=\"app.fluentcat\" time=2018-11-13 11:16:17.492985640 +0000 record={\"message\"=>\"\\xFF\\xAD\"}"}
```

Then, user should use more concrete tag route or use `@label`.
The following sections show two examples how to solve flood of declined log.
One is using concrete tag routing, the other is using label routing.

#### Using concrete tag routing

The following configuration uses concrete tag route:

```aconf
<match out.opensearch.**>
  @type opensearch
  host localhost
  port 9200
  type_name fluentd
  logstash_format true
  time_key @timestamp
  include_timestamp true
  reconnect_on_error true
  reload_on_failure true
  reload_connections false
  request_timeout 120s
</match>
```

#### Using label feature

The following configuration uses label:

```aconf
<source>
  @type forward
  @label @ES
</source>
<label @ES>
  <match out.opensearch.**>
    @type opensearch
    host localhost
    port 9200
    type_name fluentd
    logstash_format true
    time_key @timestamp
    include_timestamp true
    reconnect_on_error true
    reload_on_failure true
    reload_connections false
    request_timeout 120s
  </match>
</label>
<label @ERROR>
  <match **>
    @type stdout
  </match>
</label>
```

### Suggested to install typhoeus gem, why?

fluent-plugin-opensearch doesn't depend on typhoeus gem by default.
If you want to use typhoeus backend, you must install typhoeus gem by your own.

If you use vanilla Fluentd, you can install it by:

```
gem install typhoeus
```

But, you use td-agent instead of vanilla Fluentd, you have to use `td-agent-gem`:

```
td-agent-gem install typhoeus
```

In more detail, please refer to [the official plugin management document](https://docs.fluentd.org/v1.0/articles/plugin-management).

### Random 400 - Rejected by OpenSearch is occured, why?

Index templates installed OpenSearch sometimes generates 400 - Rejected by OpenSearch errors.
For example, kubernetes audit log has structure:

```json
"responseObject":{
   "kind":"SubjectAccessReview",
   "apiVersion":"authorization.k8s.io/v1beta1",
   "metadata":{
      "creationTimestamp":null
   },
   "spec":{
      "nonResourceAttributes":{
         "path":"/",
         "verb":"get"
      },
      "user":"system:anonymous",
      "group":[
         "system:unauthenticated"
      ]
   },
   "status":{
      "allowed":true,
      "reason":"RBAC: allowed by ClusterRoleBinding \"cluster-system-anonymous\" of ClusterRole \"cluster-admin\" to User \"system:anonymous\""
   }
},
```

The last element `status` sometimes becomes `"status":"Success"`.
This element type glich causes status 400 error.

There are some solutions for fixing this:

#### Solution 1

For a key which causes element type glich case.

Using dymanic mapping with the following template:

```json
{
  "template": "YOURINDEXNAME-*",
  "mappings": {
    "fluentd": {
      "dynamic_templates": [
        {
          "default_no_index": {
            "path_match": "^.*$",
            "path_unmatch": "^(@timestamp|auditID|level|stage|requestURI|sourceIPs|metadata|objectRef|user|verb)(\\..+)?$",
            "match_pattern": "regex",
            "mapping": {
              "index": false,
              "enabled": false
            }
          }
        }
      ]
    }
  }
}
```

Note that `YOURINDEXNAME` should be replaced with your using index prefix.

#### Solution 2

For unstable `responseObject` and `requestObject` key existence case.

```aconf
<filter YOURROUTETAG>
  @id kube_api_audit_normalize
  @type record_transformer
  auto_typecast false
  enable_ruby true
  <record>
    host "#{ENV['K8S_NODE_NAME']}"
    responseObject ${record["responseObject"].nil? ? "none": record["responseObject"].to_json}
    requestObject ${record["requestObject"].nil? ? "none": record["requestObject"].to_json}
    origin kubernetes-api-audit
  </record>
</filter>
```

Normalize `responseObject` and `requestObject` key with record_transformer and other similiar plugins is needed.

### Fluentd seems to hang if it unable to connect OpenSearch, why?

On `#configure` phase, OpenSearch plugin should wait until OpenSearch instance communication is succeeded.
And OpenSearch plugin blocks to launch Fluentd by default.
Because Fluentd requests to set up configuration correctly on `#configure` phase.

After `#configure` phase, it runs very fast and send events heavily in some heavily using case.

In this scenario, we need to set up configuration correctly until `#configure` phase.
So, we provide default parameter is too conservative to use advanced users.

To remove too pessimistic behavior, you can use the following configuration:

```aconf
<match **>
  @type opensearch
  # Some advanced users know their using OpenSearch version.
  # We can disable startup OpenSearch version checking.
  verify_os_version_at_startup false
  # If you know that your using OpenSearch major version is 7, you can set as 7 here.
  default_opensearch_version 1
  # If using very stable OpenSearch cluster, you can reduce retry operation counts. (minmum is 1)
  max_retry_get_os_version 1
  # If using very stable OpenSearch cluster, you can reduce retry operation counts. (minmum is 1)
  max_retry_putting_template 1
  # ... and some OpenSearch plugin configuration
</match>
```

### How to specify index codec

OpenSearch can handle compression methods for stored data such as LZ4 and best_compression.
fluent-plugin-opensearch doesn't provide API which specifies compression method.

Users can specify stored data compression method with template:

Create `compression.json` as follows:

```json
{
  "order": 100,
  "index_patterns": [
    "YOUR-INDEX-PATTERN"
  ],
  "settings": {
    "index": {
      "codec": "best_compression"
    }
  }
}
```

Then, specify the above template in your configuration:

```aconf
template_name best_compression_tmpl
template_file compression.json
```

OpenSearch will store data with `best_compression`:

```
% curl -XGET 'http://localhost:9200/logstash-2019.12.06/_settings?pretty'
```

```json
{
  "logstash-2019.12.06" : {
    "settings" : {
      "index" : {
        "codec" : "best_compression",
        "number_of_shards" : "1",
        "provided_name" : "logstash-2019.12.06",
        "creation_date" : "1575622843800",
        "number_of_replicas" : "1",
        "uuid" : "THE_AWESOMEUUID",
        "version" : {
          "created" : "7040100"
        }
      }
    }
  }
}
```

### Cannot push logs to OpenSearch with connect_write timeout reached, why?

It seems that OpenSearch cluster is exhausted.

Usually, Fluentd complains like the following log:

```log
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=27.283766102716327 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=26.161768959928304 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 00:23:33 +0000 [warn]: buffer flush took longer time than slow_flush_log_threshold: elapsed_time=28.713624476008117 slow_flush_log_threshold=15.0 plugin_id="object:aaaffaaaaaff"
2019-12-29 01:39:18 +0000 [warn]: Could not push logs to OpenSearch, resetting connection and trying again. connect_write timeout reached
2019-12-29 01:39:18 +0000 [warn]: Could not push logs to OpenSearch, resetting connection and trying again. connect_write timeout reached
```

This warnings is usually caused by exhaused OpenSearch cluster due to resource shortage.

If CPU usage is spiked and OpenSearch cluster is eating up CPU resource, this issue is caused by CPU resource shortage.

Check your OpenSearch cluster health status and resource usage.

### Index State Management feature is not provided, why?

From OpenSearch documentation, Index Lifecycle Management (ILM) feature is renamed to Index State Management (ISM). And it is not recommended to use from logging agents.

Also, Ruby client library has a license issue for the original ILM part. To avoid this license issue, OpenSearch Ruby client library team decided to remove this part from their Ruby client code:
https://github.com/opensearch-project/opensearch-ruby/pull/4

Index State Management (ISM) is encouraged to use via OpenSearch Dashboards that is formerly known as Kibana.

See also: https://opensearch.org/docs/latest/im-plugin/ism/index/
