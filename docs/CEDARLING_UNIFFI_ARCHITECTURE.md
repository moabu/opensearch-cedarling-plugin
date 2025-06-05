# OpenSearch Cedarling Security Plugin - UniFFI Architecture

## Overview

This document details the architectural redesign of the OpenSearch Cedarling Security Plugin to use authentic Kotlin/Java UniFFI bindings from the Janssen Project, following OpenSearch plugin design standards and proper integration patterns.

## Architectural Changes

### Previous Implementation Issues
- Used custom `CedarlingAdapter` wrapper
- Inconsistent endpoint references for embedded service
- Limited integration with Cedarling engine

### New UniFFI-Based Architecture
- Direct integration with `uniffi.cedarling_uniffi.Cedarling` class
- Authentic Janssen Project Cedarling engine
- Proper resource management with `Disposable` pattern
- Native library integration through JNA

## Core Components

### 1. EmbeddedCedarlingService.java

```java
// Authentic UniFFI bindings import
import uniffi.cedarling_uniffi.Cedarling;
import uniffi.cedarling_uniffi.AuthorizeResult;
import uniffi.cedarling_uniffi.EntityData;
import uniffi.cedarling_uniffi.Decision;

// Cedarling instance initialization
private volatile Cedarling cedarlingInstance;

// Initialization using UniFFI bindings
this.cedarlingInstance = Cedarling.Companion.loadFromJson(configJson);

// Authorization using authentic bindings
EntityData resourceEntity = EntityData.Companion.fromJson(resource.toString());
AuthorizeResult result = cedarlingInstance.authorize(tokens, action, resourceEntity, context.toString());
boolean allowed = result.getDecision() == Decision.ALLOW;
```

### 2. Build Configuration (build.gradle)

Following OpenSearch plugin architecture standards:

```gradle
buildscript {
    ext {
        opensearch_group = "org.opensearch"
        opensearch_version = System.getProperty("opensearch.version", "2.11.0-SNAPSHOT")
        opensearch_build = opensearch_version.replaceAll(/(\.\d)([^\d]*)$/, '$1.0$2')
    }
}

opensearchplugin {
    name 'opensearch-security-cedarling'
    description 'OpenSearch Cedarling Security Plugin with embedded Jans Cedarling engine'
    classname 'org.opensearch.security.cedarling.CedarlingSecurityPlugin'
}

dependencies {
    // Authentic Jans Cedarling UniFFI dependencies
    implementation "io.jans:cedarling-java:0.0.0-nightly"
    implementation "org.jetbrains.kotlin:kotlin-stdlib:1.9.20"
    implementation "net.java.dev.jna:jna:5.13.0"
}
```

### 3. Plugin Descriptor (plugin-descriptor.properties)

```properties
description=OpenSearch Cedarling Security Plugin with embedded Jans Cedarling engine
classname=org.opensearch.security.cedarling.CedarlingSecurityPlugin
has.native.controller=false
jvm.options=-Djna.library.path=${plugin.path}/lib
```

## UniFFI Integration Patterns

### 1. Resource Management

```java
@Override
public void close() {
    if (cedarlingInstance != null) {
        try {
            cedarlingInstance.shutDown();
            cedarlingInstance.destroy();
            logger.info("Embedded Cedarling service closed successfully using UniFFI bindings");
        } catch (Exception e) {
            logger.warn("Error closing embedded Cedarling service", e);
        }
    }
}
```

### 2. Error Handling

```java
try {
    AuthorizeResult result = cedarlingInstance.authorize(tokens, action, resourceEntity, context);
    return new AuthorizationResponse(allowed, reason, diagnostics);
} catch (AuthorizeException | EntityException e) {
    logger.error("Embedded Cedarling authorization failed", e);
    return new AuthorizationResponse(false, "Authorization error: " + e.getMessage(), null);
} catch (CedarlingException e) {
    logger.error("Cedarling engine error: {}", e.getMessage(), e);
    throw new RuntimeException("Cedarling operation failed", e);
}
```

### 3. Configuration Management

```java
private String buildCedarlingConfig() {
    StringBuilder configBuilder = new StringBuilder();
    configBuilder.append("{");
    configBuilder.append("\"policy_store_id\":\"").append(policyStoreId).append("\",");
    configBuilder.append("\"timeout_ms\":").append(timeoutMs).append(",");
    configBuilder.append("\"audit_enabled\":").append(auditEnabled).append(",");
    configBuilder.append("\"application_name\":\"opensearch-cedarling-plugin\"");
    configBuilder.append("}");
    return configBuilder.toString();
}
```

## OpenSearch Plugin Standards Compliance

### 1. Plugin Structure
```
src/main/java/org/opensearch/security/cedarling/
├── CedarlingSecurityPlugin.java              # Main plugin class
├── service/
│   └── EmbeddedCedarlingService.java         # UniFFI-based service
├── rest/                                     # REST API handlers
├── model/                                    # Data models
└── config/                                   # Configuration
```

### 2. Settings Management
```java
public static final Setting<Boolean> CEDARLING_ENABLED = Setting.boolSetting(
    "cedarling.enabled",
    true,
    Setting.Property.NodeScope,
    Setting.Property.Dynamic
);
```

### 3. Action Registration
```java
@Override
public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
    return Arrays.asList(
        new ActionHandler<>(CedarlingAuthorizationAction.INSTANCE, TransportCedarlingAuthorizationAction.class)
    );
}
```

## Security Considerations

### 1. Native Library Permissions
```properties
java.opts=-Djava.security.policy=security.policy
jvm.options=-Djna.library.path=${plugin.path}/lib
```

### 2. Resource Isolation
- Proper cleanup with `Disposable` pattern
- Thread-safe access to Cedarling instance
- Timeout management for authorization requests

### 3. Configuration Security
- Sensitive settings marked as `Property.Filtered`
- Secure credential handling for policy store access
- Audit logging for all authorization decisions

## Performance Optimizations

### 1. Instance Management
```java
private volatile Cedarling cedarlingInstance;  // Thread-safe singleton
```

### 2. Async Operations
```java
return CompletableFuture.supplyAsync(() -> {
    // Authorization logic
}, threadPool.executor(ThreadPool.Names.GENERIC))
.orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
```

### 3. Resource Pooling
- Reuse Cedarling instance across requests
- Efficient JSON serialization/deserialization
- Minimal object allocation in hot paths

## Testing Strategy

### 1. Unit Tests
- Mock UniFFI bindings for isolated testing
- Verify proper resource cleanup
- Test error handling scenarios

### 2. Integration Tests
```java
public class CedarlingSecurityPluginIntegrationTest extends OpenSearchIntegTestCase {
    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(CedarlingSecurityPlugin.class);
    }
}
```

### 3. Performance Tests
- Authorization latency benchmarks
- Memory usage profiling
- Concurrent request handling

## Deployment Considerations

### 1. Native Dependencies
- Ensure JNA libraries are available
- Proper library path configuration
- Platform-specific native bindings

### 2. Configuration
```yaml
cedarling:
  enabled: true
  policy_store_id: "opensearch-security-store"
  timeout_ms: 5000
  audit:
    enabled: true
    metrics:
      enabled: true
```

### 3. Monitoring
- Health check endpoints
- Performance metrics
- Error rate monitoring

## Migration Path

### From Previous Implementation
1. Update dependencies to use authentic UniFFI bindings
2. Replace `CedarlingAdapter` with direct `Cedarling` usage
3. Update configuration to remove endpoint references
4. Test authorization flows with new bindings
5. Validate performance improvements

### Rollback Strategy
- Keep previous implementation in separate branch
- Gradual deployment with feature flags
- Comprehensive testing before full rollout

## Future Enhancements

### 1. Policy Management
- Dynamic policy loading
- Policy versioning support
- Real-time policy updates

### 2. Performance
- Connection pooling
- Caching strategies
- Batch authorization requests

### 3. Monitoring
- Enhanced metrics collection
- Distributed tracing
- Advanced analytics

This architectural redesign ensures the OpenSearch Cedarling Security Plugin follows best practices for both OpenSearch plugin development and authentic Janssen Project Cedarling integration.