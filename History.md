## Changelog [[tags]](https://github.com/fluent/fluent-plugin-opensearch/tags)

### [Unreleased]

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
