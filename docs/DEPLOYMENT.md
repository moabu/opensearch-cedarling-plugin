# OpenSearch Cedarling Security Plugin - Deployment Guide

This guide provides comprehensive instructions for building, loading, and testing the OpenSearch Cedarling Security Plugin in production environments.

## Quick Start

```bash
# 1. Build the plugin
gradle clean build -x test

# 2. Install plugin
bin/opensearch-plugin install file:///path/to/opensearch-security-cedarling-2.11.0.0.jar

# 3. Configure OpenSearch
echo "plugins.security.cedarling.enabled: true" >> config/opensearch.yml

# 4. Start OpenSearch
bin/opensearch

# 5. Test plugin
curl -X GET "localhost:9200/_plugins/_cedarling/status"
```

## Detailed Build Instructions

### Prerequisites

- **Java**: OpenJDK 11 or later
- **Gradle**: 8.0 or later
- **OpenSearch**: 2.11.0
- **Memory**: Minimum 4GB RAM for building
- **Disk**: 2GB free space for build artifacts

### Building from Source

1. **Clone Repository**:
   ```bash
   git clone <repository-url>
   cd opensearch-cedarling-security-plugin
   ```

2. **Verify Dependencies**:
   ```bash
   java -version  # Should show Java 11+
   gradle --version  # Should show Gradle 8.0+
   ```

3. **Build Plugin JAR**:
   ```bash
   # Clean build without tests (faster)
   gradle clean build -x test
   
   # Full build with tests
   gradle clean build
   
   # Build with specific OpenSearch version
   gradle clean build -Dopensearch.version=2.11.0
   ```

4. **Verify Build Output**:
   ```bash
   ls -la opensearch-security-cedarling-2.11.0.0.jar
   # Expected: ~150KB JAR file
   
   # Check JAR contents
   jar -tf opensearch-security-cedarling-2.11.0.0.jar | head -20
   ```

### Build Troubleshooting

**Common Build Issues:**

1. **Gradle Daemon Issues**:
   ```bash
   gradle --stop
   gradle clean build --no-daemon
   ```

2. **Memory Issues**:
   ```bash
   export GRADLE_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m"
   gradle clean build
   ```

3. **Dependency Resolution**:
   ```bash
   gradle dependencies --configuration compileClasspath
   gradle build --refresh-dependencies
   ```

## Plugin Installation Methods

### Method 1: OpenSearch Plugin CLI (Recommended)

1. **Local Installation**:
   ```bash
   # Stop OpenSearch if running
   pkill -f opensearch
   
   # Install plugin
   bin/opensearch-plugin install file:///absolute/path/to/opensearch-security-cedarling-2.11.0.0.jar
   
   # Verify installation
   bin/opensearch-plugin list
   ```

2. **Remote Installation**:
   ```bash
   # Install from URL
   bin/opensearch-plugin install https://releases.example.com/opensearch-security-cedarling-2.11.0.0.jar
   
   # Install with specific permissions
   bin/opensearch-plugin install --batch file:///path/to/plugin.jar
   ```

### Method 2: Manual Installation

1. **Create Plugin Directory**:
   ```bash
   mkdir -p $OPENSEARCH_HOME/plugins/opensearch-security-cedarling
   cd $OPENSEARCH_HOME/plugins/opensearch-security-cedarling
   ```

2. **Copy Plugin Files**:
   ```bash
   # Copy JAR
   cp /path/to/opensearch-security-cedarling-2.11.0.0.jar .
   
   # Create plugin descriptor
   cat > plugin-descriptor.properties << 'EOF'
   description=OpenSearch Cedarling Security Plugin with embedded Jans Cedarling engine
   version=2.11.0.0
   name=opensearch-security-cedarling
   classname=org.opensearch.security.cedarling.CedarlingSecurityPlugin
   java.version=11
   opensearch.version=2.11.0
   has.native.controller=false
   requires.keystore=false
   EOF
   ```

3. **Set Permissions**:
   ```bash
   chmod 644 opensearch-security-cedarling-2.11.0.0.jar
   chmod 644 plugin-descriptor.properties
   chown -R opensearch:opensearch $OPENSEARCH_HOME/plugins/opensearch-security-cedarling
   ```

### Method 3: Docker Installation

1. **Dockerfile**:
   ```dockerfile
   FROM opensearchproject/opensearch:2.11.0
   
   # Copy plugin
   COPY opensearch-security-cedarling-2.11.0.0.jar /tmp/
   
   # Install plugin
   RUN bin/opensearch-plugin install file:///tmp/opensearch-security-cedarling-2.11.0.0.jar
   
   # Configure Cedarling
   RUN echo "plugins.security.cedarling.enabled: true" >> config/opensearch.yml
   ```

2. **Build and Run**:
   ```bash
   docker build -t opensearch-cedarling .
   docker run -p 9200:9200 -e "discovery.type=single-node" opensearch-cedarling
   ```

## Configuration

### Basic Configuration

Add to `config/opensearch.yml`:

```yaml
# Cedarling Plugin Configuration
plugins.security.cedarling.enabled: true
plugins.security.cedarling.policy_store_id: opensearch-security-store
plugins.security.cedarling.timeout_ms: 5000

# Disable default security if using Cedarling
plugins.security.disabled: false
plugins.security.ssl.transport.enabled: false
plugins.security.ssl.http.enabled: false

# Performance settings
plugins.security.cedarling.cache.enabled: true
plugins.security.cedarling.cache.size: 10000
plugins.security.cedarling.cache.ttl_seconds: 300
```

### Production Configuration

```yaml
# Production OpenSearch with Cedarling
cluster.name: production-cedarling-cluster
node.name: cedarling-node-1
network.host: 0.0.0.0
http.port: 9200

# Cedarling Production Settings
plugins.security.cedarling.enabled: true
plugins.security.cedarling.policy_store_id: production-policy-store
plugins.security.cedarling.timeout_ms: 3000
plugins.security.cedarling.audit.enabled: true
plugins.security.cedarling.audit.log_level: INFO
plugins.security.cedarling.circuit_breaker.enabled: true
plugins.security.cedarling.circuit_breaker.failure_threshold: 10

# Performance Optimizations
bootstrap.memory_lock: true
indices.memory.index_buffer_size: 20%
thread_pool.search.queue_size: 2000
thread_pool.write.queue_size: 1000

# JVM Settings
-Xms2g
-Xmx2g
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
```

### Environment Variables

```bash
# Production environment
export OPENSEARCH_JAVA_OPTS="-Xms4g -Xmx4g"
export CEDARLING_POLICY_STORE_URL="https://jans.production.com/cedarling"
export CEDARLING_JWKS_URI="https://jans.production.com/.well-known/jwks"
export CEDARLING_CLIENT_ID="opensearch-cedarling-client"
```

## Testing the Plugin

### 1. Startup Testing

```bash
# Start OpenSearch with verbose logging
bin/opensearch -E logger.org.opensearch.security.cedarling=DEBUG

# Check startup logs
tail -f logs/opensearch.log | grep -i cedarling

# Expected log entries:
# [INFO ][o.o.s.c.CedarlingSecurityPlugin] Initializing Cedarling Security Plugin
# [INFO ][o.o.s.c.CedarlingSecurityPlugin] Cedarling plugin loaded successfully
```

### 2. Plugin Status Verification

```bash
# Basic cluster info
curl -X GET "localhost:9200/"

# Plugin-specific status
curl -X GET "localhost:9200/_plugins/_cedarling/status"

# Expected response:
{
  "plugin": "opensearch-security-cedarling",
  "version": "2.11.0.0",
  "status": "active",
  "cedarling_engine": "embedded",
  "policy_store": "opensearch-security-store",
  "statistics": {
    "total_requests": 0,
    "allowed_requests": 0,
    "denied_requests": 0,
    "average_response_time_ms": 0.0
  }
}
```

### 3. Authorization Testing

```bash
# Test basic authorization
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/authorize" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user:alice@example.com",
    "action": "read",
    "resource": "index:customer-data",
    "context": {"account_id": "acct_123", "department": "sales"}
  }'

# Expected response:
{
  "decision": "ALLOW",
  "policies_applied": ["CustomerDataAccess"],
  "execution_time_ms": 2.1,
  "principal": "user:alice@example.com",
  "action": "read",
  "resource": "index:customer-data",
  "timestamp": "2024-06-05T10:47:23Z"
}
```

### 4. Schema and Policy Testing

```bash
# Create test schema
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/schema" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestSchema",
    "definition": "entity User = { account_id: String, department: String }; entity Document = { account_id: String, classification: String }; action read, write, delete;"
  }'

# Create test policy
curl -X POST "localhost:9200/_plugins/_cedarling/data-policies/policy" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestPolicy",
    "definition": "permit(principal == User::\"alice@example.com\", action == Action::\"read\", resource) when { principal.account_id == resource.account_id };"
  }'
```

### 5. Performance Testing

```bash
# Performance test script
for i in {1..100}; do
  curl -s -X POST "localhost:9200/_plugins/_cedarling/data-policies/authorize" \
    -H "Content-Type: application/json" \
    -d '{"principal":"user:test'$i'@example.com","action":"read","resource":"index:test"}' \
    | jq '.execution_time_ms'
done | awk '{ sum += $1; count++ } END { print "Average: " sum/count "ms" }'
```

### 6. Load Testing

```bash
# Install Apache Bench
apt-get update && apt-get install -y apache2-utils

# Load test authorization endpoint
ab -n 1000 -c 10 -T 'application/json' \
  -p authorization_request.json \
  http://localhost:9200/_plugins/_cedarling/data-policies/authorize

# authorization_request.json content:
cat > authorization_request.json << 'EOF'
{
  "principal": "user:loadtest@example.com",
  "action": "read",
  "resource": "index:loadtest-data",
  "context": {"account_id": "acct_loadtest"}
}
EOF
```

## Web Interface Testing

### 1. Data Policy Interface

```bash
# Open in browser or test with curl
curl -X GET "localhost:9200/_plugins/_cedarling/data-policies"

# Should return HTML interface with:
# - Authorization request form
# - Schema management
# - Policy management
# - Audit dashboard
```

### 2. TBAC Demo Interface

```bash
# Test TBAC demo
curl -X GET "localhost:9200/_plugins/_cedarling/tbac/demo"

# Should return HTML showing:
# - Token information
# - Ext object metadata
# - Authorization results
# - Policy evaluation flow
```

## Production Deployment

### 1. Multi-Node Cluster Setup

```yaml
# Node 1 (Master)
cluster.name: production-cedarling
node.name: cedarling-master-1
node.roles: [cluster_manager, data]
discovery.seed_hosts: ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
cluster.initial_cluster_manager_nodes: ["cedarling-master-1"]

# Node 2 (Data)
cluster.name: production-cedarling
node.name: cedarling-data-1
node.roles: [data]
discovery.seed_hosts: ["10.0.1.1", "10.0.1.2", "10.0.1.3"]

# Node 3 (Data)
cluster.name: production-cedarling
node.name: cedarling-data-2
node.roles: [data]
discovery.seed_hosts: ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
```

### 2. Load Balancer Configuration

```nginx
# Nginx configuration
upstream opensearch_cedarling {
    server 10.0.1.1:9200;
    server 10.0.1.2:9200;
    server 10.0.1.3:9200;
}

server {
    listen 80;
    server_name opensearch.example.com;
    
    location / {
        proxy_pass http://opensearch_cedarling;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /_plugins/_cedarling/ {
        proxy_pass http://opensearch_cedarling;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Health Checks

```bash
#!/bin/bash
# healthcheck.sh

# Check OpenSearch cluster health
CLUSTER_HEALTH=$(curl -s "localhost:9200/_cluster/health" | jq -r '.status')
if [ "$CLUSTER_HEALTH" != "green" ] && [ "$CLUSTER_HEALTH" != "yellow" ]; then
    echo "Cluster health is $CLUSTER_HEALTH"
    exit 1
fi

# Check Cedarling plugin status
PLUGIN_STATUS=$(curl -s "localhost:9200/_plugins/_cedarling/status" | jq -r '.status')
if [ "$PLUGIN_STATUS" != "active" ]; then
    echo "Cedarling plugin status is $PLUGIN_STATUS"
    exit 1
fi

# Test authorization endpoint
AUTH_TEST=$(curl -s -X POST "localhost:9200/_plugins/_cedarling/data-policies/authorize" \
  -H "Content-Type: application/json" \
  -d '{"principal":"healthcheck","action":"read","resource":"healthcheck"}' | jq -r '.decision')
  
if [ -z "$AUTH_TEST" ]; then
    echo "Authorization endpoint not responding"
    exit 1
fi

echo "All health checks passed"
exit 0
```

### 4. Monitoring and Metrics

```bash
# Monitor plugin metrics
curl -X GET "localhost:9200/_nodes/stats/plugins"

# Monitor authorization performance
curl -X GET "localhost:9200/_plugins/_cedarling/metrics"

# Check plugin logs
tail -f logs/opensearch.log | grep cedarling

# Monitor JVM metrics
curl -X GET "localhost:9200/_nodes/stats/jvm"
```

## Troubleshooting

### Plugin Loading Issues

1. **Plugin Not Found**:
   ```bash
   # Check plugin directory
   ls -la plugins/opensearch-security-cedarling/
   
   # Verify descriptor
   cat plugins/opensearch-security-cedarling/plugin-descriptor.properties
   
   # Check permissions
   ls -la plugins/opensearch-security-cedarling/opensearch-security-cedarling-2.11.0.0.jar
   ```

2. **ClassNotFoundException**:
   ```bash
   # Check Java version
   java -version
   
   # Verify JAR contents
   jar -tf opensearch-security-cedarling-2.11.0.0.jar | grep CedarlingSecurityPlugin
   
   # Check OpenSearch logs for detailed error
   grep -A 20 "CedarlingSecurityPlugin" logs/opensearch.log
   ```

### Authorization Issues

1. **Authorization Failures**:
   ```bash
   # Check Cedarling engine status
   curl -X GET "localhost:9200/_plugins/_cedarling/status"
   
   # Enable debug logging
   curl -X PUT "localhost:9200/_cluster/settings" \
     -H "Content-Type: application/json" \
     -d '{"transient":{"logger.org.opensearch.security.cedarling":"DEBUG"}}'
   
   # Check audit logs
   tail -f logs/opensearch_audit.log | grep cedarling
   ```

2. **Performance Issues**:
   ```bash
   # Check thread pool stats
   curl -X GET "localhost:9200/_nodes/stats/thread_pool"
   
   # Monitor GC
   tail -f logs/gc.log
   
   # Check circuit breaker stats
   curl -X GET "localhost:9200/_nodes/stats/breaker"
   ```

### Recovery Procedures

1. **Plugin Removal**:
   ```bash
   # Stop OpenSearch
   pkill -f opensearch
   
   # Remove plugin
   bin/opensearch-plugin remove opensearch-security-cedarling
   
   # Restart OpenSearch
   bin/opensearch
   ```

2. **Plugin Reinstallation**:
   ```bash
   # Clean removal
   rm -rf plugins/opensearch-security-cedarling
   
   # Fresh installation
   bin/opensearch-plugin install file:///path/to/opensearch-security-cedarling-2.11.0.0.jar
   ```

## Security Considerations

### 1. Network Security

```yaml
# Restrict plugin endpoints
http.cors.enabled: true
http.cors.allow-origin: "https://trusted-domain.com"
http.cors.allow-methods: OPTIONS, HEAD, GET, POST
http.cors.allow-headers: X-Requested-With, X-Auth-Token, Content-Type, Content-Length
```

### 2. Authentication Integration

```bash
# Configure with external auth provider
export CEDARLING_OIDC_ISSUER="https://auth.example.com"
export CEDARLING_OIDC_CLIENT_ID="opensearch-client"
export CEDARLING_OIDC_CLIENT_SECRET="secret"
```

### 3. Audit Configuration

```yaml
# Enable comprehensive auditing
plugins.security.cedarling.audit.enabled: true
plugins.security.cedarling.audit.log_level: INFO
plugins.security.cedarling.audit.include_request_body: true
plugins.security.cedarling.audit.include_response_body: false
```

## Performance Tuning

### 1. JVM Tuning

```bash
# Production JVM settings
export OPENSEARCH_JAVA_OPTS="
  -Xms8g
  -Xmx8g
  -XX:+UseG1GC
  -XX:G1HeapRegionSize=32m
  -XX:+UnlockExperimentalVMOptions
  -XX:+UseStringDeduplication
  -XX:MaxGCPauseMillis=200
"
```

### 2. Cedarling Cache Tuning

```yaml
# Optimize Cedarling performance
plugins.security.cedarling.cache.enabled: true
plugins.security.cedarling.cache.size: 50000
plugins.security.cedarling.cache.ttl_seconds: 600
plugins.security.cedarling.thread_pool.size: 10
plugins.security.cedarling.queue_size: 1000
```

### 3. Circuit Breaker Configuration

```yaml
# Prevent cascading failures
plugins.security.cedarling.circuit_breaker.enabled: true
plugins.security.cedarling.circuit_breaker.failure_threshold: 5
plugins.security.cedarling.circuit_breaker.success_threshold: 3
plugins.security.cedarling.circuit_breaker.timeout_seconds: 60
```

This deployment guide provides comprehensive instructions for successfully building, loading, and testing the OpenSearch Cedarling Security Plugin in production environments.