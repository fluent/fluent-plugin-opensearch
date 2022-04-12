## Changelog [[tags]](https://github.com/fluent/fluent-plugin-opensearch/tags)

### [Unreleased]

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
