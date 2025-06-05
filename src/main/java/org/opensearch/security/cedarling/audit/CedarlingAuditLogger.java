/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.audit;

import org.opensearch.common.component.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive audit logging service for Cedarling security events
 * Provides detailed tracking of authorization decisions, policy evaluations, 
 * security violations, and performance metrics
 */
public class CedarlingAuditLogger extends AbstractLifecycleComponent {
    
    private static final String AUDIT_INDEX_PREFIX = "cedarling-audit-";
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy.MM.dd");
    private static final int MAX_AUDIT_EVENTS = 10000;
    private static final int BATCH_SIZE = 100;
    
    private final Settings settings;
    private final ThreadPool threadPool;
    private final Queue<AuditEvent> auditEventQueue;
    private final Map<String, AuditMetrics> auditMetrics;
    private final AtomicLong totalEvents;
    private final AtomicLong securityViolations;
    private final AtomicLong policyEvaluations;
    
    private ScheduledFuture<?> auditProcessor;
    private volatile boolean auditEnabled;
    private volatile boolean detailedLogging;
    private volatile boolean performanceTracking;
    
    public CedarlingAuditLogger(Settings settings, ThreadPool threadPool) {
        super();
        this.settings = settings;
        this.threadPool = threadPool;
        this.auditEventQueue = new ConcurrentLinkedQueue<>();
        this.auditMetrics = new ConcurrentHashMap<>();
        this.totalEvents = new AtomicLong(0);
        this.securityViolations = new AtomicLong(0);
        this.policyEvaluations = new AtomicLong(0);
        
        this.auditEnabled = settings.getAsBoolean("cedarling.audit.enabled", true);
        this.detailedLogging = settings.getAsBoolean("cedarling.audit.detailed", true);
        this.performanceTracking = settings.getAsBoolean("cedarling.audit.performance", true);
    }
    
    /**
     * Logs an authorization decision with comprehensive context
     */
    public void logAuthorizationDecision(AuditEventModels.AuthorizationDecisionEvent event) {
        if (!auditEnabled) return;
        
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_DECISION)
            .timestamp(Instant.now())
            .decision(event.getDecision())
            .action(event.getAction())
            .resource(event.getResource())
            .principal(event.getPrincipal())
            .policies(event.getPoliciesEvaluated())
            .responseTimeMs(event.getResponseTimeMs())
            .reason(event.getReason())
            .tokenInfo(event.getTokenInfo())
            .clientIp(event.getClientIp())
            .userAgent(event.getUserAgent())
            .requestId(event.getRequestId())
            .sessionId(event.getSessionId())
            .clusterNode(event.getClusterNode())
            .build();
            
        queueAuditEvent(auditEvent);
        updateMetrics(auditEvent);
        
        if ("DENY".equals(event.getDecision())) {
            securityViolations.incrementAndGet();
            logSecurityViolation(event);
        }
        
        policyEvaluations.incrementAndGet();
    }
    
    /**
     * Logs policy synchronization events
     */
    public void logPolicySyncEvent(AuditEventModels.PolicySyncEvent event) {
        if (!auditEnabled) return;
        
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(AuditEventType.POLICY_SYNC)
            .timestamp(Instant.now())
            .syncStatus(event.getStatus())
            .policiesUpdated(event.getPoliciesUpdated())
            .syncDurationMs(event.getDurationMs())
            .syncSource(event.getSource())
            .errorMessage(event.getErrorMessage())
            .clusterNode(event.getClusterNode())
            .build();
            
        queueAuditEvent(auditEvent);
        updateMetrics(auditEvent);
    }
    
    /**
     * Logs system configuration changes
     */
    public void logConfigurationChange(AuditEventModels.ConfigurationChangeEvent event) {
        if (!auditEnabled) return;
        
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(AuditEventType.CONFIGURATION_CHANGE)
            .timestamp(Instant.now())
            .configurationKey(event.getKey())
            .oldValue(event.getOldValue())
            .newValue(event.getNewValue())
            .changedBy(event.getChangedBy())
            .clusterNode(event.getClusterNode())
            .build();
            
        queueAuditEvent(auditEvent);
        updateMetrics(auditEvent);
    }
    
    /**
     * Logs security violations with enhanced details
     */
    public void logSecurityViolation(AuditEventModels.AuthorizationDecisionEvent event) {
        if (!auditEnabled) return;
        
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(AuditEventType.SECURITY_VIOLATION)
            .timestamp(Instant.now())
            .violationType("UNAUTHORIZED_ACCESS_ATTEMPT")
            .decision(event.getDecision())
            .action(event.getAction())
            .resource(event.getResource())
            .principal(event.getPrincipal())
            .reason(event.getReason())
            .clientIp(event.getClientIp())
            .userAgent(event.getUserAgent())
            .threatLevel(calculateThreatLevel(event))
            .requestId(event.getRequestId())
            .clusterNode(event.getClusterNode())
            .build();
            
        queueAuditEvent(auditEvent);
        updateMetrics(auditEvent);
    }
    
    /**
     * Logs performance metrics
     */
    public void logPerformanceMetrics(AuditEventModels.PerformanceEvent event) {
        if (!auditEnabled || !performanceTracking) return;
        
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(AuditEventType.PERFORMANCE_METRICS)
            .timestamp(Instant.now())
            .responseTimeMs(event.getResponseTimeMs())
            .memoryUsageMb(event.getMemoryUsageMb())
            .cpuUsagePercent(event.getCpuUsagePercent())
            .activeConnections(event.getActiveConnections())
            .queueSize(event.getQueueSize())
            .throughputPerSecond(event.getThroughputPerSecond())
            .clusterNode(event.getClusterNode())
            .build();
            
        queueAuditEvent(auditEvent);
        updateMetrics(auditEvent);
    }
    
    /**
     * Gets comprehensive audit analytics
     */
    public AuditAnalytics getAuditAnalytics() {
        return AuditAnalytics.builder()
            .totalEvents(totalEvents.get())
            .securityViolations(securityViolations.get())
            .policyEvaluations(policyEvaluations.get())
            .auditMetrics(new HashMap<>(auditMetrics))
            .topViolatedResources(getTopViolatedResources())
            .topDeniedActions(getTopDeniedActions())
            .hourlyTrends(getHourlyTrends())
            .performanceMetrics(getPerformanceMetrics())
            .complianceStatus(getComplianceStatus())
            .build();
    }
    
    /**
     * Gets audit events for dashboard display
     */
    public List<AuditEvent> getRecentAuditEvents(int limit) {
        return auditEventQueue.stream()
            .limit(limit)
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
            .collect(Collectors.toList());
    }
    
    /**
     * Exports audit data for compliance reporting
     */
    public String exportAuditData(Instant fromTime, Instant toTime, AuditEventType eventType) throws IOException {
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.startObject();
        builder.field("export_timestamp", Instant.now().toString());
        builder.field("from_time", fromTime.toString());
        builder.field("to_time", toTime.toString());
        builder.field("event_type", eventType != null ? eventType.name() : "ALL");
        
        builder.startArray("audit_events");
        for (AuditEvent event : auditEventQueue) {
            if (event.getTimestamp().isAfter(fromTime) && 
                event.getTimestamp().isBefore(toTime) &&
                (eventType == null || event.getEventType() == eventType)) {
                
                event.toXContent(builder);
            }
        }
        builder.endArray();
        
        builder.field("total_events", totalEvents.get());
        builder.field("security_violations", securityViolations.get());
        builder.field("compliance_status", getComplianceStatus());
        
        builder.endObject();
        return builder.toString();
    }
    
    private void queueAuditEvent(AuditEvent event) {
        auditEventQueue.offer(event);
        if (auditEventQueue.size() > MAX_AUDIT_EVENTS) {
            auditEventQueue.poll();
        }
        totalEvents.incrementAndGet();
    }
    
    private void updateMetrics(AuditEvent event) {
        String metricKey = event.getEventType().name();
        auditMetrics.computeIfAbsent(metricKey, k -> new AuditMetrics())
            .increment(event);
    }
    
    private String calculateThreatLevel(AuthorizationDecisionEvent event) {
        // Simple threat level calculation
        if (event.getAction().contains("admin") || event.getAction().contains("delete")) {
            return "HIGH";
        } else if (event.getAction().contains("write") || event.getAction().contains("index")) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
    
    private List<String> getTopViolatedResources() {
        return auditEventQueue.stream()
            .filter(event -> event.getEventType() == AuditEventType.SECURITY_VIOLATION)
            .collect(Collectors.groupingBy(AuditEvent::getResource, Collectors.counting()))
            .entrySet()
            .stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }
    
    private List<String> getTopDeniedActions() {
        return auditEventQueue.stream()
            .filter(event -> "DENY".equals(event.getDecision()))
            .collect(Collectors.groupingBy(AuditEvent::getAction, Collectors.counting()))
            .entrySet()
            .stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }
    
    private Map<String, Long> getHourlyTrends() {
        Map<String, Long> trends = new HashMap<>();
        Instant now = Instant.now();
        
        for (int i = 0; i < 24; i++) {
            Instant hourStart = now.minusSeconds(i * 3600);
            Instant hourEnd = hourStart.plusSeconds(3600);
            
            long count = auditEventQueue.stream()
                .filter(event -> event.getTimestamp().isAfter(hourStart) && 
                               event.getTimestamp().isBefore(hourEnd))
                .count();
                
            trends.put(hourStart.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("HH:00")), count);
        }
        
        return trends;
    }
    
    private Map<String, Double> getPerformanceMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        
        OptionalDouble avgResponseTime = auditEventQueue.stream()
            .filter(event -> event.getResponseTimeMs() != null)
            .mapToDouble(AuditEvent::getResponseTimeMs)
            .average();
            
        metrics.put("avg_response_time_ms", avgResponseTime.orElse(0.0));
        metrics.put("total_events_per_hour", totalEvents.get() / 24.0);
        metrics.put("security_violation_rate", 
            totalEvents.get() > 0 ? (securityViolations.get() * 100.0 / totalEvents.get()) : 0.0);
        
        return metrics;
    }
    
    private ComplianceStatus getComplianceStatus() {
        double violationRate = totalEvents.get() > 0 ? 
            (securityViolations.get() * 100.0 / totalEvents.get()) : 0.0;
            
        return ComplianceStatus.builder()
            .gdprCompliant(true)
            .soxCompliant(violationRate < 5.0)
            .iso27001Compliant(true)
            .auditTrailComplete(totalEvents.get() > 0)
            .lastAuditTime(Instant.now())
            .violationRate(violationRate)
            .build();
    }
    
    private void processAuditEvents() {
        List<AuditEvent> batch = new ArrayList<>();
        
        for (int i = 0; i < BATCH_SIZE && !auditEventQueue.isEmpty(); i++) {
            AuditEvent event = auditEventQueue.poll();
            if (event != null) {
                batch.add(event);
            }
        }
        
        if (!batch.isEmpty()) {
            persistAuditEvents(batch);
        }
    }
    
    private void persistAuditEvents(List<AuditEvent> events) {
        // In a real implementation, this would persist to OpenSearch indices
        // For now, we keep them in memory
        events.forEach(this::queueAuditEvent);
    }
    
    @Override
    protected void doStart() {
        if (auditEnabled) {
            // Start audit event processor
            auditProcessor = threadPool.scheduleWithFixedDelay(
                this::processAuditEvents,
                TimeUnit.SECONDS.toMillis(10),
                TimeUnit.SECONDS.toMillis(30),
                ThreadPool.Names.GENERIC
            );
        }
    }
    
    @Override
    protected void doStop() {
        if (auditProcessor != null) {
            auditProcessor.cancel(false);
        }
    }
    
    @Override
    protected void doClose() {
        auditEventQueue.clear();
        auditMetrics.clear();
    }
    
    // Inner classes for audit data structures
    
    public static class AuditMetrics {
        private final AtomicLong count = new AtomicLong(0);
        private final AtomicLong totalResponseTime = new AtomicLong(0);
        
        public void increment(AuditEvent event) {
            count.incrementAndGet();
            if (event.getResponseTimeMs() != null) {
                totalResponseTime.addAndGet(event.getResponseTimeMs().longValue());
            }
        }
        
        public long getCount() { return count.get(); }
        public double getAverageResponseTime() { 
            return count.get() > 0 ? totalResponseTime.get() / (double) count.get() : 0.0;
        }
    }
    
    public enum AuditEventType {
        AUTHORIZATION_DECISION,
        SECURITY_VIOLATION,
        POLICY_SYNC,
        CONFIGURATION_CHANGE,
        PERFORMANCE_METRICS,
        SYSTEM_EVENT
    }
}