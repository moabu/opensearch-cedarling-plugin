/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.audit;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Comprehensive audit analytics and compliance reporting
 */
public class AuditAnalytics {
    
    private final long totalEvents;
    private final long securityViolations;
    private final long policyEvaluations;
    private final Map<String, CedarlingAuditLogger.AuditMetrics> auditMetrics;
    private final List<String> topViolatedResources;
    private final List<String> topDeniedActions;
    private final Map<String, Long> hourlyTrends;
    private final Map<String, Double> performanceMetrics;
    private final ComplianceStatus complianceStatus;
    
    private AuditAnalytics(Builder builder) {
        this.totalEvents = builder.totalEvents;
        this.securityViolations = builder.securityViolations;
        this.policyEvaluations = builder.policyEvaluations;
        this.auditMetrics = builder.auditMetrics;
        this.topViolatedResources = builder.topViolatedResources;
        this.topDeniedActions = builder.topDeniedActions;
        this.hourlyTrends = builder.hourlyTrends;
        this.performanceMetrics = builder.performanceMetrics;
        this.complianceStatus = builder.complianceStatus;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public long getTotalEvents() { return totalEvents; }
    public long getSecurityViolations() { return securityViolations; }
    public long getPolicyEvaluations() { return policyEvaluations; }
    public Map<String, CedarlingAuditLogger.AuditMetrics> getAuditMetrics() { return auditMetrics; }
    public List<String> getTopViolatedResources() { return topViolatedResources; }
    public List<String> getTopDeniedActions() { return topDeniedActions; }
    public Map<String, Long> getHourlyTrends() { return hourlyTrends; }
    public Map<String, Double> getPerformanceMetrics() { return performanceMetrics; }
    public ComplianceStatus getComplianceStatus() { return complianceStatus; }
    
    public static class Builder {
        private long totalEvents;
        private long securityViolations;
        private long policyEvaluations;
        private Map<String, CedarlingAuditLogger.AuditMetrics> auditMetrics;
        private List<String> topViolatedResources;
        private List<String> topDeniedActions;
        private Map<String, Long> hourlyTrends;
        private Map<String, Double> performanceMetrics;
        private ComplianceStatus complianceStatus;
        
        public Builder totalEvents(long totalEvents) {
            this.totalEvents = totalEvents;
            return this;
        }
        
        public Builder securityViolations(long securityViolations) {
            this.securityViolations = securityViolations;
            return this;
        }
        
        public Builder policyEvaluations(long policyEvaluations) {
            this.policyEvaluations = policyEvaluations;
            return this;
        }
        
        public Builder auditMetrics(Map<String, CedarlingAuditLogger.AuditMetrics> auditMetrics) {
            this.auditMetrics = auditMetrics;
            return this;
        }
        
        public Builder topViolatedResources(List<String> topViolatedResources) {
            this.topViolatedResources = topViolatedResources;
            return this;
        }
        
        public Builder topDeniedActions(List<String> topDeniedActions) {
            this.topDeniedActions = topDeniedActions;
            return this;
        }
        
        public Builder hourlyTrends(Map<String, Long> hourlyTrends) {
            this.hourlyTrends = hourlyTrends;
            return this;
        }
        
        public Builder performanceMetrics(Map<String, Double> performanceMetrics) {
            this.performanceMetrics = performanceMetrics;
            return this;
        }
        
        public Builder complianceStatus(ComplianceStatus complianceStatus) {
            this.complianceStatus = complianceStatus;
            return this;
        }
        
        public AuditAnalytics build() {
            return new AuditAnalytics(this);
        }
    }
}

/**
 * Compliance status for regulatory requirements
 */
class ComplianceStatus {
    private final boolean gdprCompliant;
    private final boolean soxCompliant;
    private final boolean iso27001Compliant;
    private final boolean auditTrailComplete;
    private final Instant lastAuditTime;
    private final double violationRate;
    
    private ComplianceStatus(Builder builder) {
        this.gdprCompliant = builder.gdprCompliant;
        this.soxCompliant = builder.soxCompliant;
        this.iso27001Compliant = builder.iso27001Compliant;
        this.auditTrailComplete = builder.auditTrailComplete;
        this.lastAuditTime = builder.lastAuditTime;
        this.violationRate = builder.violationRate;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public boolean isGdprCompliant() { return gdprCompliant; }
    public boolean isSoxCompliant() { return soxCompliant; }
    public boolean isIso27001Compliant() { return iso27001Compliant; }
    public boolean isAuditTrailComplete() { return auditTrailComplete; }
    public Instant getLastAuditTime() { return lastAuditTime; }
    public double getViolationRate() { return violationRate; }
    
    public static class Builder {
        private boolean gdprCompliant;
        private boolean soxCompliant;
        private boolean iso27001Compliant;
        private boolean auditTrailComplete;
        private Instant lastAuditTime;
        private double violationRate;
        
        public Builder gdprCompliant(boolean gdprCompliant) {
            this.gdprCompliant = gdprCompliant;
            return this;
        }
        
        public Builder soxCompliant(boolean soxCompliant) {
            this.soxCompliant = soxCompliant;
            return this;
        }
        
        public Builder iso27001Compliant(boolean iso27001Compliant) {
            this.iso27001Compliant = iso27001Compliant;
            return this;
        }
        
        public Builder auditTrailComplete(boolean auditTrailComplete) {
            this.auditTrailComplete = auditTrailComplete;
            return this;
        }
        
        public Builder lastAuditTime(Instant lastAuditTime) {
            this.lastAuditTime = lastAuditTime;
            return this;
        }
        
        public Builder violationRate(double violationRate) {
            this.violationRate = violationRate;
            return this;
        }
        
        public ComplianceStatus build() {
            return new ComplianceStatus(this);
        }
    }
}