# OpenSearch Cedarling Security Plugin - Clean Project Structure

## Project Overview
Pure embedded OpenSearch security plugin with Janssen Project Cedarling engine using authentic UniFFI bindings. No external service dependencies required.

## Final Project Structure
```
opensearch-cedarling-plugin/
├── build.gradle                           # Gradle build with UniFFI dependencies
├── src/
│   ├── main/
│   │   ├── java/org/opensearch/security/cedarling/
│   │   │   ├── CedarlingSecurityPlugin.java       # Main plugin class
│   │   │   ├── service/EmbeddedCedarlingService.java # UniFFI service
│   │   │   ├── rest/RestCedarlingPolicyInterfaceHandler.java
│   │   │   └── [other source files]
│   │   └── resources/
│   │       └── plugin-descriptor.properties       # Plugin configuration
│   └── test/                              # Test files
├── cedarling_uniffi.kt                    # Authentic Janssen UniFFI bindings
├── README.md                              # Project documentation
├── CEDARLING_UNIFFI_ARCHITECTURE.md       # Technical architecture
├── EMBEDDED_CEDARLING_INTEGRATION.md      # Integration guide
├── DEPLOYMENT.md                          # Production deployment
└── opensearch-plugin-deployment-demo.py   # Working demonstration
```

## Architecture Principles
- **Embedded Only**: No external Cedarling service required
- **UniFFI Native**: Direct uniffi.cedarling_uniffi.Cedarling integration
- **Zero Dependencies**: Fully self-contained within OpenSearch
- **Standard Compliance**: Follows OpenSearch plugin architecture standards

## Configuration
```yaml
cedarling:
  enabled: true
  policy_store_id: "opensearch-security-store"
  timeout_ms: 5000
  audit:
    enabled: true
```

No CEDARLING_ENDPOINT configuration needed - engine is embedded.

## Key Benefits
- Sub-millisecond authorization decisions
- No network latency for policy evaluation
- Simplified deployment and maintenance
- Enhanced security through embedded architecture
- Native performance with Rust-based engine