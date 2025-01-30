## Changelog [[tags]](https://github.com/fluent/fluent-plugin-opensearch/tags)

### [Unreleased]

### 1.1.5
 - Fix bundle installation error on GitHub Action (#143)
 - Prevent AWS credentials refresh from stopping on exception (#142)
 - Added a retry logic and a service availability check function for high availability. (#136)
 - out\_opensearch\_data\_stream: Early return on empty body (#131)
 - Docs/cleanup issue templates (#119)
 - pin dependency opensearch-ruby to 3.0.1 (#116)

### 1.1.4
 - test: remove minitest to correct misjudge of the framework by flexmock (#114)
 - Add logic to write method of out_opensearch_data_stream (#109)

### 1.1.3
 - Revert the behavior of passing duration second (#108)

### 1.1.2
 - Check OS cluster for data streams and templates for index template creation (#106)
 - out\_opensearch\_data\_stream: Don't connect to opensearch on dry-run (#105)

### 1.1.1
 -  Pass a value of refresh\_credentials\_interval as duration\_seconds (#78)

### 1.1.0
 - Unpin `faraday` from v1, upgrade to v2.
   Note that if you can't migrate other plugins from `faraday` v1 yet, need to keep
   fluent-plugin-opensearch v1.0.10.

### 1.0.10
 - Replace File.exists? with File.exist? to work with Ruby 3.2 (#93)
 - Add a constraint for dependent gem to stay on Faraday v1 (#90)
 - README.md: Fix a link to opensearch-ruby (#85)

### 1.0.9
 - Adjust GitHub workflows (#89)
 - out\_opensearch: Provide service_name choices for handling serverless (#88)

### 1.0.8
 - Use faraday 1.x explicitly (#71)

### 1.0.7
 - Expire AWS credentials with a certain interval (#52)

### 1.0.6
 - out\_opensearch: Handle suppress\_type\_name operation correctly (#61)

### 1.0.5
 -  Use if clause to detect requirements for emitting error label events (#57)
 - opensearch_data_stream: Align lowercases for data_stream and its template names (#50)

### 1.0.4
 - Automatically create data streams (#44)

### 1.0.3
 - Configurable unrecoverable record types (#40)
 - Handle exceptions on retrieving AWS credentials (#39)
 - Suppress emit error label events (#38)
 - Provide suppress_type_name parameter (#29)
 - Honor @time_key (data streams) (#28)

### 1.0.2
 - Honor @hosts parameter for Data Streams (#21)
 - Use template_file for Data Streams (#20)
 - Specify host argument if needed (#11)

### 1.0.1
 -  Add testcases for hosts parameter (#10)
 - Permit to handle @hosts parameter (#9)
 - Retry creating data stream/template when OpenSearch is unreachable (#8)

### 1.0.0
 - Initial public gem release.
