/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.audit;

import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Comprehensive audit event data model for Cedarling security events
 */
public class AuditEvent {
    
    private final CedarlingAuditLogger.AuditEventType eventType;
    private final Instant timestamp;
    private final String decision;
    private final String action;
    private final String resource;
    private final String principal;
    private final List<String> policies;
    private final Double responseTimeMs;
    private final String reason;
    private final Map<String, Object> tokenInfo;
    private final String clientIp;
    private final String userAgent;
    private final String requestId;
    private final String sessionId;
    private final String clusterNode;
    
    // Policy sync specific fields
    private final String syncStatus;
    private final List<String> policiesUpdated;
    private final Long syncDurationMs;
    private final String syncSource;
    private final String errorMessage;
    
    // Configuration change fields
    private final String configurationKey;
    private final String oldValue;
    private final String newValue;
    private final String changedBy;
    
    // Security violation fields
    private final String violationType;
    private final String threatLevel;
    
    // Performance metrics fields
    private final Double memoryUsageMb;
    private final Double cpuUsagePercent;
    private final Integer activeConnections;
    private final Integer queueSize;
    private final Double throughputPerSecond;
    
    private AuditEvent(Builder builder) {
        this.eventType = builder.eventType;
        this.timestamp = builder.timestamp;
        this.decision = builder.decision;
        this.action = builder.action;
        this.resource = builder.resource;
        this.principal = builder.principal;
        this.policies = builder.policies;
        this.responseTimeMs = builder.responseTimeMs;
        this.reason = builder.reason;
        this.tokenInfo = builder.tokenInfo;
        this.clientIp = builder.clientIp;
        this.userAgent = builder.userAgent;
        this.requestId = builder.requestId;
        this.sessionId = builder.sessionId;
        this.clusterNode = builder.clusterNode;
        this.syncStatus = builder.syncStatus;
        this.policiesUpdated = builder.policiesUpdated;
        this.syncDurationMs = builder.syncDurationMs;
        this.syncSource = builder.syncSource;
        this.errorMessage = builder.errorMessage;
        this.configurationKey = builder.configurationKey;
        this.oldValue = builder.oldValue;
        this.newValue = builder.newValue;
        this.changedBy = builder.changedBy;
        this.violationType = builder.violationType;
        this.threatLevel = builder.threatLevel;
        this.memoryUsageMb = builder.memoryUsageMb;
        this.cpuUsagePercent = builder.cpuUsagePercent;
        this.activeConnections = builder.activeConnections;
        this.queueSize = builder.queueSize;
        this.throughputPerSecond = builder.throughputPerSecond;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public void toXContent(XContentBuilder builder) throws IOException {
        builder.startObject();
        builder.field("event_type", eventType.name());
        builder.field("timestamp", timestamp.toString());
        
        if (decision != null) builder.field("decision", decision);
        if (action != null) builder.field("action", action);
        if (resource != null) builder.field("resource", resource);
        if (principal != null) builder.field("principal", principal);
        if (policies != null) builder.field("policies", policies);
        if (responseTimeMs != null) builder.field("response_time_ms", responseTimeMs);
        if (reason != null) builder.field("reason", reason);
        if (tokenInfo != null) builder.field("token_info", tokenInfo);
        if (clientIp != null) builder.field("client_ip", clientIp);
        if (userAgent != null) builder.field("user_agent", userAgent);
        if (requestId != null) builder.field("request_id", requestId);
        if (sessionId != null) builder.field("session_id", sessionId);
        if (clusterNode != null) builder.field("cluster_node", clusterNode);
        
        // Policy sync fields
        if (syncStatus != null) builder.field("sync_status", syncStatus);
        if (policiesUpdated != null) builder.field("policies_updated", policiesUpdated);
        if (syncDurationMs != null) builder.field("sync_duration_ms", syncDurationMs);
        if (syncSource != null) builder.field("sync_source", syncSource);
        if (errorMessage != null) builder.field("error_message", errorMessage);
        
        // Configuration change fields
        if (configurationKey != null) builder.field("configuration_key", configurationKey);
        if (oldValue != null) builder.field("old_value", oldValue);
        if (newValue != null) builder.field("new_value", newValue);
        if (changedBy != null) builder.field("changed_by", changedBy);
        
        // Security violation fields
        if (violationType != null) builder.field("violation_type", violationType);
        if (threatLevel != null) builder.field("threat_level", threatLevel);
        
        // Performance fields
        if (memoryUsageMb != null) builder.field("memory_usage_mb", memoryUsageMb);
        if (cpuUsagePercent != null) builder.field("cpu_usage_percent", cpuUsagePercent);
        if (activeConnections != null) builder.field("active_connections", activeConnections);
        if (queueSize != null) builder.field("queue_size", queueSize);
        if (throughputPerSecond != null) builder.field("throughput_per_second", throughputPerSecond);
        
        builder.endObject();
    }
    
    // Getters
    public CedarlingAuditLogger.AuditEventType getEventType() { return eventType; }
    public Instant getTimestamp() { return timestamp; }
    public String getDecision() { return decision; }
    public String getAction() { return action; }
    public String getResource() { return resource; }
    public String getPrincipal() { return principal; }
    public List<String> getPolicies() { return policies; }
    public Double getResponseTimeMs() { return responseTimeMs; }
    public String getReason() { return reason; }
    public Map<String, Object> getTokenInfo() { return tokenInfo; }
    public String getClientIp() { return clientIp; }
    public String getUserAgent() { return userAgent; }
    public String getRequestId() { return requestId; }
    public String getSessionId() { return sessionId; }
    public String getClusterNode() { return clusterNode; }
    public String getSyncStatus() { return syncStatus; }
    public List<String> getPoliciesUpdated() { return policiesUpdated; }
    public Long getSyncDurationMs() { return syncDurationMs; }
    public String getSyncSource() { return syncSource; }
    public String getErrorMessage() { return errorMessage; }
    public String getConfigurationKey() { return configurationKey; }
    public String getOldValue() { return oldValue; }
    public String getNewValue() { return newValue; }
    public String getChangedBy() { return changedBy; }
    public String getViolationType() { return violationType; }
    public String getThreatLevel() { return threatLevel; }
    public Double getMemoryUsageMb() { return memoryUsageMb; }
    public Double getCpuUsagePercent() { return cpuUsagePercent; }
    public Integer getActiveConnections() { return activeConnections; }
    public Integer getQueueSize() { return queueSize; }
    public Double getThroughputPerSecond() { return throughputPerSecond; }
    
    public static class Builder {
        private CedarlingAuditLogger.AuditEventType eventType;
        private Instant timestamp;
        private String decision;
        private String action;
        private String resource;
        private String principal;
        private List<String> policies;
        private Double responseTimeMs;
        private String reason;
        private Map<String, Object> tokenInfo;
        private String clientIp;
        private String userAgent;
        private String requestId;
        private String sessionId;
        private String clusterNode;
        private String syncStatus;
        private List<String> policiesUpdated;
        private Long syncDurationMs;
        private String syncSource;
        private String errorMessage;
        private String configurationKey;
        private String oldValue;
        private String newValue;
        private String changedBy;
        private String violationType;
        private String threatLevel;
        private Double memoryUsageMb;
        private Double cpuUsagePercent;
        private Integer activeConnections;
        private Integer queueSize;
        private Double throughputPerSecond;
        
        public Builder eventType(CedarlingAuditLogger.AuditEventType eventType) {
            this.eventType = eventType;
            return this;
        }
        
        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }
        
        public Builder decision(String decision) {
            this.decision = decision;
            return this;
        }
        
        public Builder action(String action) {
            this.action = action;
            return this;
        }
        
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }
        
        public Builder principal(String principal) {
            this.principal = principal;
            return this;
        }
        
        public Builder policies(List<String> policies) {
            this.policies = policies;
            return this;
        }
        
        public Builder responseTimeMs(Double responseTimeMs) {
            this.responseTimeMs = responseTimeMs;
            return this;
        }
        
        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }
        
        public Builder tokenInfo(Map<String, Object> tokenInfo) {
            this.tokenInfo = tokenInfo;
            return this;
        }
        
        public Builder clientIp(String clientIp) {
            this.clientIp = clientIp;
            return this;
        }
        
        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }
        
        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }
        
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }
        
        public Builder clusterNode(String clusterNode) {
            this.clusterNode = clusterNode;
            return this;
        }
        
        public Builder syncStatus(String syncStatus) {
            this.syncStatus = syncStatus;
            return this;
        }
        
        public Builder policiesUpdated(List<String> policiesUpdated) {
            this.policiesUpdated = policiesUpdated;
            return this;
        }
        
        public Builder syncDurationMs(Long syncDurationMs) {
            this.syncDurationMs = syncDurationMs;
            return this;
        }
        
        public Builder syncSource(String syncSource) {
            this.syncSource = syncSource;
            return this;
        }
        
        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }
        
        public Builder configurationKey(String configurationKey) {
            this.configurationKey = configurationKey;
            return this;
        }
        
        public Builder oldValue(String oldValue) {
            this.oldValue = oldValue;
            return this;
        }
        
        public Builder newValue(String newValue) {
            this.newValue = newValue;
            return this;
        }
        
        public Builder changedBy(String changedBy) {
            this.changedBy = changedBy;
            return this;
        }
        
        public Builder violationType(String violationType) {
            this.violationType = violationType;
            return this;
        }
        
        public Builder threatLevel(String threatLevel) {
            this.threatLevel = threatLevel;
            return this;
        }
        
        public Builder memoryUsageMb(Double memoryUsageMb) {
            this.memoryUsageMb = memoryUsageMb;
            return this;
        }
        
        public Builder cpuUsagePercent(Double cpuUsagePercent) {
            this.cpuUsagePercent = cpuUsagePercent;
            return this;
        }
        
        public Builder activeConnections(Integer activeConnections) {
            this.activeConnections = activeConnections;
            return this;
        }
        
        public Builder queueSize(Integer queueSize) {
            this.queueSize = queueSize;
            return this;
        }
        
        public Builder throughputPerSecond(Double throughputPerSecond) {
            this.throughputPerSecond = throughputPerSecond;
            return this;
        }
        
        public AuditEvent build() {
            return new AuditEvent(this);
        }
    }
}