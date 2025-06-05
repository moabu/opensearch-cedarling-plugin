# OpenSearch Security Cedarling Plugin

An enterprise-grade OpenSearch security plugin that integrates Cedarling for advanced data policy authorization and real-time security management.

## Features

- **Token-Based Access Control (TBAC)**: Real-time JWT token validation and policy enforcement
- **Data Policy Authorization**: Granular control over document and field-level access
- **Cedarling Integration**: Native integration with Jans Cedarling policy engine via UniFFI
- **Comprehensive Audit Logging**: Detailed security event tracking and analytics
- **Post-Query Enforcement**: Cedar policy evaluation after query execution
- **Multi-Environment Support**: Flexible deployment across development and production

## Quick Start

### Build the Plugin

```bash
./gradlew build
```

### Install and Run

1. Copy the plugin JAR to your OpenSearch plugins directory:
```bash
cp build/distributions/opensearch-security-cedarling-2.11.0.0.zip $OPENSEARCH_HOME/plugins/
cd $OPENSEARCH_HOME && bin/opensearch-plugin install file:///path/to/opensearch-security-cedarling-2.11.0.0.zip
```

2. Start OpenSearch:
```bash
$OPENSEARCH_HOME/bin/opensearch
```

### Demo and Testing

Run the live TBAC demonstration:
```bash
python demo/tbac-live-demo.py
# Access: http://localhost:8080

python demo/opensearch-cedarling-production.py  
# Plugin API: http://localhost:5000
```

## Architecture

- **Plugin Core**: Java-based OpenSearch plugin with Cedarling engine integration
- **Policy Engine**: Embedded Cedarling service with Cedar policy evaluation
- **REST Handlers**: Comprehensive API endpoints for policy management
- **Security Filters**: Pre and post-query enforcement mechanisms
- **Audit System**: Event tracking with analytics and reporting

## API Endpoints

- `/_plugins/_cedarling/status` - Plugin status and health
- `/_plugins/_cedarling/data-policies/authorize` - Authorization requests
- `/_plugins/_cedarling/data-policies` - Policy management interface
- `/_plugins/_cedarling/tbac/demo` - TBAC testing interface
- `/_plugins/_cedarling/audit/analytics` - Audit analytics dashboard

## Configuration

Add to `opensearch.yml`:
```yaml
plugins.security.cedarling.enabled: true
plugins.security.cedarling.policy_store.type: "opensearch"
plugins.security.cedarling.audit.enabled: true
plugins.security.cedarling.tbac.enabled: true
```

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md)
- [TBAC Implementation](docs/TBAC_COMPLETE_DEMO.md)
- [Architecture Overview](docs/EMBEDDED_CEDARLING_INTEGRATION.md)
- [Plugin Summary](docs/FINAL_PLUGIN_SUMMARY.md)

## Requirements

- OpenSearch 2.11.0+
- Java 11+
- Gradle 7.5+

## License

Apache License 2.0 - See [LICENSE.txt](LICENSE.txt)

## Contributing

This plugin follows OpenSearch security plugin standards and integrates with the Janssen Project's Cedarling service for enterprise-grade authorization capabilities.