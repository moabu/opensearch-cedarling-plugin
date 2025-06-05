# Comprehensive Audit Logging System

## Overview

The OpenSearch Cedarling Security Plugin now includes a comprehensive audit logging system that tracks all security-related events, policy decisions, and compliance metrics. This system provides enterprise-grade audit capabilities for regulatory compliance and security monitoring.

## Features

### Core Audit Capabilities
- **Authorization Decision Tracking**: Every policy evaluation is logged with complete context
- **Performance Metrics**: Response times, throughput, and resource utilization tracking
- **Compliance Reporting**: GDPR, SOX, and ISO 27001 compliance status monitoring
- **Security Violation Detection**: Automated detection and logging of security violations
- **Policy Synchronization Events**: Complete audit trail of policy updates and changes

### Event Types
1. **AUTHORIZATION_DECISION**: Policy evaluation results with full context
2. **POLICY_SYNC**: Policy store synchronization events
3. **CONFIGURATION_CHANGE**: System configuration modifications
4. **SECURITY_VIOLATION**: Security policy violations and threats
5. **PERFORMANCE_METRIC**: System performance and health metrics

## API Endpoints

### Audit Analytics Dashboard
```
GET /_plugins/_cedarling/audit/dashboard
```
Interactive dashboard with real-time visualizations and compliance reporting.

### Audit Analytics Data
```
GET /_plugins/_cedarling/audit/analytics
```
Returns comprehensive audit analytics including:
- Total events count
- Security violations summary
- Policy evaluation metrics
- Top violated resources
- Hourly trends
- Performance metrics
- Compliance status

### Audit Events Retrieval
```
GET /_plugins/_cedarling/audit/events?limit=100
```
Retrieves recent audit events with detailed information.

### Audit Data Export
```
GET /_plugins/_cedarling/audit/export?from=2024-01-01T00:00:00Z&to=2024-12-31T23:59:59Z&event_type=AUTHORIZATION_DECISION
```
Exports audit data for compliance reporting and analysis.

### Test Event Generation
```
POST /_plugins/_cedarling/audit/test
```
Generates test audit events for system validation.

## Event Data Model

### Authorization Decision Event
```json
{
  "event_type": "AUTHORIZATION_DECISION",
  "timestamp": "2024-06-04T10:30:00Z",
  "decision": "DENY",
  "action": "indices:admin/delete",
  "resource": "sensitive-logs-index",
  "principal": "user:john.doe",
  "policies": ["admin_access_policy", "data_protection_policy"],
  "response_time_ms": 1.2,
  "reason": "Insufficient privileges for admin operation",
  "token_info": {
    "token_type": "bearer",
    "client_id": "opensearch-client",
    "roles": ["user", "analyst"]
  },
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "request_id": "req-1234567890",
  "session_id": "session-abcdef123",
  "cluster_node": "node-1"
}
```

### Security Violation Event
```json
{
  "event_type": "SECURITY_VIOLATION",
  "timestamp": "2024-06-04T10:30:00Z",
  "violation_type": "UNAUTHORIZED_ACCESS_ATTEMPT",
  "threat_level": "HIGH",
  "principal": "user:suspicious.user",
  "resource": "admin-only-index",
  "reason": "Multiple failed authorization attempts",
  "client_ip": "203.0.113.45"
}
```

## Compliance Features

### GDPR Compliance
- Data subject identification in audit logs
- Data access tracking
- Consent management audit trail
- Data retention policy enforcement

### SOX Compliance
- Financial data access monitoring
- Change management audit trail
- Segregation of duties enforcement
- Management reporting capabilities

### ISO 27001 Compliance
- Information security event logging
- Access control monitoring
- Incident response tracking
- Risk assessment data collection

## Configuration

### Enable Comprehensive Audit Logging
```yaml
plugins.security.cedarling.audit.enabled: true
plugins.security.cedarling.audit.retention_days: 365
plugins.security.cedarling.audit.export_enabled: true
plugins.security.cedarling.audit.compliance_reporting: true
```

### Audit Event Filters
```yaml
plugins.security.cedarling.audit.include_events:
  - AUTHORIZATION_DECISION
  - SECURITY_VIOLATION
  - POLICY_SYNC
plugins.security.cedarling.audit.exclude_users:
  - system
  - health-check
```

## Integration with Cedarling Engine

The audit logging system is fully integrated with the embedded Cedarling engine:

1. **Automatic Event Generation**: Every authorization decision automatically creates an audit event
2. **Policy Context**: Audit events include complete policy evaluation context
3. **Performance Tracking**: Sub-millisecond response time tracking for all operations
4. **Error Handling**: Comprehensive error logging with detailed diagnostics

## Analytics and Reporting

### Real-Time Dashboard
- Live policy decision monitoring
- Security violation alerts
- Performance metrics visualization
- Compliance status indicators

### Trend Analysis
- Hourly, daily, and monthly trends
- Access pattern analysis
- Resource utilization monitoring
- Policy effectiveness metrics

### Compliance Reports
- Automated compliance status reports
- Audit trail completeness verification
- Violation rate analysis
- Risk assessment data

## Security Considerations

### Data Protection
- Audit logs are encrypted at rest
- Sensitive data is masked in logs
- Access to audit data is restricted
- Tamper-evident logging mechanisms

### Performance Impact
- Minimal performance overhead (<1ms per event)
- Asynchronous logging to prevent blocking
- Efficient storage and indexing
- Configurable retention policies

## Usage Examples

### Query Recent Authorization Decisions
```bash
curl -X GET "localhost:9200/_plugins/_cedarling/audit/events?limit=50" \
  -H "Content-Type: application/json"
```

### Export Compliance Report
```bash
curl -X GET "localhost:9200/_plugins/_cedarling/audit/export?from=2024-01-01T00:00:00Z&to=2024-12-31T23:59:59Z" \
  -H "Content-Type: application/json" \
  -o compliance-report.json
```

### Access Analytics Dashboard
```bash
# Open in browser
http://localhost:9200/_plugins/_cedarling/audit/dashboard
```

## Monitoring and Alerting

### Health Checks
- Audit system health monitoring
- Event processing rate tracking
- Storage capacity monitoring
- Compliance status verification

### Alert Conditions
- Security violation thresholds
- Policy evaluation failures
- Compliance status changes
- Performance degradation

## Best Practices

1. **Regular Monitoring**: Check audit dashboard daily for security events
2. **Compliance Reviews**: Conduct quarterly compliance status reviews
3. **Performance Optimization**: Monitor audit system performance impact
4. **Data Retention**: Configure appropriate retention policies for compliance
5. **Access Control**: Restrict audit data access to authorized personnel only

## Troubleshooting

### Common Issues
- **High Memory Usage**: Adjust retention policies and export frequency
- **Slow Performance**: Configure asynchronous logging and indexing
- **Missing Events**: Verify audit configuration and filters
- **Export Failures**: Check storage permissions and capacity

### Diagnostics
```bash
# Check audit system health
curl -X GET "localhost:9200/_plugins/_cedarling/audit/analytics"

# Verify configuration
curl -X GET "localhost:9200/_cluster/settings"
```

This comprehensive audit logging system ensures complete visibility into all security-related activities while maintaining compliance with major regulatory frameworks.