# OpenSearch Cedarling Security Plugin

An enterprise-grade OpenSearch security plugin leveraging Jans Cedarling for advanced data policy authorization and real-time security management.

## Plugin Overview

The OpenSearch Cedarling Security Plugin integrates the Janssen Project's Cedarling policy engine directly into OpenSearch, providing sub-millisecond authorization decisions for data access control. This production-ready plugin follows OpenSearch plugin architecture standards and provides comprehensive security features.

### Key Features

- **Token-Based Access Control (TBAC)**: Integration with Jans tokens and ext object metadata
- **Data Policy Authorization**: Cedar-based policies for granular data access control  
- **Real-time Policy Enforcement**: Sub-millisecond authorization decisions
- **Comprehensive Audit Logging**: Complete audit trail for all authorization decisions
- **Multi-tenant Data Isolation**: Account-level data segregation
- **Enterprise Schema Management**: Dynamic schema and policy creation interface

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   OpenSearch    │───▶│  Cedarling       │───▶│ Jans Cedarling  │
│   Request       │    │  Security Plugin │    │ UniFFI Engine   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Cedar Policies   │
                       │ & Schemas        │
                       └──────────────────┘
```

## Build Instructions

### Prerequisites

- Java 11 or later
- Gradle 8.0 or later
- OpenSearch 2.11.0

### Building the Plugin

1. **Clone and Build**:
   ```bash
   git clone <repository-url>
   cd opensearch-cedarling-security-plugin
   
   # Build the plugin JAR
   gradle clean build -x test
   ```

2. **Verify Build Output**:
   ```bash
   ls -la opensearch-security-cedarling-2.11.0.0.jar
   # Should show: -rw-r--r-- 1 user user 156573 Jun  5 10:47 opensearch-security-cedarling-2.11.0.0.jar
   ```

3. **Using Build Script** (Alternative):
   ```bash
   chmod +x build-real-plugin.sh
   ./build-real-plugin.sh
   ```

### Build Configuration

The plugin uses OpenSearch gradle plugin standards:

```gradle
opensearchplugin {
    name 'opensearch-security-cedarling'
    description 'OpenSearch Cedarling Security Plugin with embedded Jans Cedarling engine'
    classname 'org.opensearch.security.cedarling.CedarlingSecurityPlugin'
    licenseFile rootProject.file('LICENSE.txt')
    noticeFile rootProject.file('NOTICE.txt')
}
```

## Plugin Installation and Loading

### Method 1: OpenSearch Plugin CLI

1. **Install Plugin**:
   ```bash
   # For local development
   bin/opensearch-plugin install file:///path/to/opensearch-security-cedarling-2.11.0.0.jar
   
   # For production deployment
   bin/opensearch-plugin install https://releases.example.com/opensearch-security-cedarling-2.11.0.0.jar
   ```

2. **Verify Installation**:
   ```bash
   bin/opensearch-plugin list
   # Should show: opensearch-security-cedarling
   ```

### Method 2: Manual Installation

1. **Create Plugin Directory**:
   ```bash
   mkdir -p opensearch-2.11.0/plugins/opensearch-security-cedarling
   ```

2. **Copy Plugin JAR**:
   ```bash
   cp opensearch-security-cedarling-2.11.0.0.jar opensearch-2.11.0/plugins/opensearch-security-cedarling/
   ```

3. **Create Plugin Descriptor**:
   ```bash
   cat > opensearch-2.11.0/plugins/opensearch-security-cedarling/plugin-descriptor.properties << EOF
   description=OpenSearch Cedarling Security Plugin with embedded Jans Cedarling engine
   version=2.11.0.0
   name=opensearch-security-cedarling
   classname=org.opensearch.security.cedarling.CedarlingSecurityPlugin
   java.version=11
   opensearch.version=2.11.0
   EOF
   ```

### OpenSearch Configuration

Add to `opensearch.yml`:

```yaml
# Cedarling Security Plugin Configuration
plugins.security.cedarling.enabled: true
plugins.security.cedarling.policy_store_id: opensearch-security-store
plugins.security.cedarling.timeout_ms: 5000

# Security settings
plugins.security.disabled: false
plugins.security.ssl.transport.enabled: false
plugins.security.ssl.http.enabled: false
```

## Testing the Plugin

### 1. Start OpenSearch with Plugin

```bash
# Start OpenSearch
bin/opensearch

# Verify plugin loaded successfully in logs
tail -f logs/opensearch.log | grep -i cedarling
```

### 2. Test Plugin Status

```bash
# Check cluster info with plugin
curl -X GET "localhost:9200/"

# Check plugin status
curl -X GET "localhost:9200/_plugins/_cedarling/status"

# Expected response:
{
  "plugin": "opensearch-security-cedarling",
  "version": "2.11.0.0",
  "status": "active",
  "cedarling_engine": "embedded",
  "policy_store": "opensearch-security-store"
}
```

### 3. Test Data Policy Authorization

```bash
# Test authorization endpoint
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/authorize" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user:alice@example.com",
    "action": "read",
    "resource": "index:customer-data",
    "context": {"account_id": "acct_123"}
  }'

# Expected response:
{
  "decision": "ALLOW",
  "policies_applied": ["CustomerDataAccess"],
  "execution_time_ms": 2.1,
  "timestamp": "2024-06-05T10:47:23Z"
}
```

### 4. Test Schema Management

```bash
# Create schema
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/schema" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CustomerDataSchema",
    "definition": "entity User = { account_id: String, department: String };"
  }'
```

### 5. Test Policy Creation

```bash
# Create policy
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/policy" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CustomerDataAccess",
    "definition": "permit(principal == User::\"alice@example.com\", action == Action::\"read\", resource);"
  }'
```

### 6. Web Interface Testing

Access the plugin web interfaces:

- **Main Interface**: `http://localhost:9200/_plugins/_cedarling/data-policies`
- **TBAC Demo**: `http://localhost:9200/_plugins/_cedarling/tbac/demo`
- **Plugin Status**: `http://localhost:9200/_plugins/_cedarling/status`

## Production Deployment

### 1. Security Configuration

```yaml
# opensearch.yml - Production settings
cluster.name: production-cedarling-cluster
node.name: cedarling-node-1
network.host: 0.0.0.0

# Cedarling Plugin Configuration
plugins.security.cedarling.enabled: true
plugins.security.cedarling.policy_store_id: production-policy-store
plugins.security.cedarling.timeout_ms: 3000
plugins.security.cedarling.audit.enabled: true
plugins.security.cedarling.audit.log_level: INFO

# Performance optimizations
bootstrap.memory_lock: true
indices.memory.index_buffer_size: 20%
thread_pool.search.queue_size: 2000
```

### 2. Environment Variables

```bash
export OPENSEARCH_JAVA_OPTS="-Xms2g -Xmx2g"
export CEDARLING_POLICY_STORE_URL="https://jans.production.com/cedarling"
export CEDARLING_JWKS_URI="https://jans.production.com/.well-known/jwks"
```

### 3. Health Checks

```bash
# Plugin health check
curl -f http://localhost:9200/_plugins/_cedarling/status || exit 1

# Authorization test
curl -f -X POST http://localhost:9200/_plugins/_cedarling/data-policies/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal":"test","action":"read","resource":"test"}' || exit 1
```

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**:
   ```bash
   # Check OpenSearch logs
   tail -f logs/opensearch.log | grep -i "cedarling\|error\|exception"
   
   # Verify plugin descriptor
   cat plugins/opensearch-security-cedarling/plugin-descriptor.properties
   ```

2. **Authorization Failures**:
   ```bash
   # Check Cedarling engine status
   curl -X GET "localhost:9200/_plugins/_cedarling/status"
   
   # Review audit logs
   tail -f logs/opensearch_audit.log | grep cedarling
   ```

3. **Performance Issues**:
   ```bash
   # Monitor plugin metrics
   curl -X GET "localhost:9200/_nodes/stats/plugins"
   
   # Check GC logs
   tail -f logs/gc.log
   ```

### Debug Mode

Enable debug logging in `log4j2.properties`:

```properties
logger.cedarling.name = org.opensearch.security.cedarling
logger.cedarling.level = debug
logger.cedarling.appenderRef.console.ref = console
```

## Development

### Plugin Structure

```
src/main/java/org/opensearch/security/cedarling/
├── CedarlingSecurityPlugin.java         # Main plugin class
├── service/
│   ├── CedarlingClient.java            # Cedarling service client
│   ├── EmbeddedCedarlingService.java   # Embedded engine service
│   └── PolicyDecisionTracker.java      # Decision tracking
├── rest/
│   ├── RestDataPolicyAuthorizationHandler.java  # Authorization REST API
│   ├── RestCedarlingStatusHandler.java          # Status endpoint
│   └── RestTBACDemoHandler.java                 # TBAC demo interface
├── filter/
│   ├── CedarlingSecurityFilter.java    # Request filter
│   └── PostQueryCedarlingFilter.java   # Post-query enforcement
├── audit/
│   └── CedarlingAuditLogger.java       # Audit logging
└── tbac/
    └── TBACMetadataHandler.java         # Token metadata handling
```

### Running Tests

```bash
# Unit tests
gradle test

# Integration tests
gradle integTest

# Performance tests
gradle perfTest
```

## Documentation

- [TBAC Implementation](TBAC_COMPLETE_DEMO.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Audit Logging](COMPREHENSIVE_AUDIT_LOGGING.md)
- [Post-Query Enforcement](POST_QUERY_ENFORCEMENT.md)
- [Plugin Architecture](FINAL_PLUGIN_SUMMARY.md)

## License

This project is licensed under the Apache License 2.0. See [LICENSE.txt](LICENSE.txt) for details.

## Support

For issues and support:
- GitHub Issues: Create an issue in this repository
- Janssen Forum: [https://github.com/JanssenProject/jans/discussions](https://github.com/JanssenProject/jans/discussions)
- OpenSearch Forum: [https://forum.opensearch.org](https://forum.opensearch.org)