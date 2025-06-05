package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.cedarling.audit.AuditMetrics;
import org.opensearch.security.cedarling.audit.AnalyticsReport;

import java.io.IOException;
import java.time.Instant;

/**
 * Response for audit and analytics operations
 */
public class CedarlingAuditResponse extends ActionResponse implements ToXContentObject {
    
    private String action;
    private boolean success;
    private String message;
    private AuditMetrics metrics;
    private AnalyticsReport analyticsReport;
    
    public CedarlingAuditResponse() {}
    
    public CedarlingAuditResponse(String action, boolean success, String message) {
        this.action = action;
        this.success = success;
        this.message = message;
    }
    
    public CedarlingAuditResponse(String action, boolean success, String message, AuditMetrics metrics) {
        this.action = action;
        this.success = success;
        this.message = message;
        this.metrics = metrics;
    }
    
    public CedarlingAuditResponse(String action, boolean success, String message, AnalyticsReport analyticsReport) {
        this.action = action;
        this.success = success;
        this.message = message;
        this.analyticsReport = analyticsReport;
    }
    
    public CedarlingAuditResponse(StreamInput in) throws IOException {
        super(in);
        this.action = in.readString();
        this.success = in.readBoolean();
        this.message = in.readOptionalString();
        
        // Read metrics if present
        if (in.readBoolean()) {
            long totalRequests = in.readLong();
            long allowedRequests = in.readLong();
            long deniedRequests = in.readLong();
            long errorRequests = in.readLong();
            
            this.metrics = new AuditMetrics(
                totalRequests,
                allowedRequests,
                deniedRequests,
                errorRequests,
                in.readMap(StreamInput::readString, StreamInput::readLong),
                in.readMap(StreamInput::readString, StreamInput::readLong),
                in.readMap(StreamInput::readString, StreamInput::readLong)
            );
        }
        
        // Read analytics report if present
        if (in.readBoolean()) {
            double threatScore = in.readDouble();
            this.analyticsReport = new AnalyticsReport(
                threatScore,
                in.readMap(),
                in.readMap(),
                in.readMap(),
                in.readMap(),
                in.readInstant()
            );
        }
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(action);
        out.writeBoolean(success);
        out.writeOptionalString(message);
        
        // Write metrics if present
        if (metrics != null) {
            out.writeBoolean(true);
            out.writeLong(metrics.getTotalRequests());
            out.writeLong(metrics.getAllowedRequests());
            out.writeLong(metrics.getDeniedRequests());
            out.writeLong(metrics.getErrorRequests());
            out.writeMap(metrics.getActionMetrics(), StreamOutput::writeString, StreamOutput::writeLong);
            out.writeMap(metrics.getTenantMetrics(), StreamOutput::writeString, StreamOutput::writeLong);
            out.writeMap(metrics.getUserMetrics(), StreamOutput::writeString, StreamOutput::writeLong);
        } else {
            out.writeBoolean(false);
        }
        
        // Write analytics report if present
        if (analyticsReport != null) {
            out.writeBoolean(true);
            out.writeDouble(analyticsReport.getThreatScore());
            out.writeGenericValue(analyticsReport.getPerformanceAnalysis());
            out.writeGenericValue(analyticsReport.getUserBehaviorAnalysis());
            out.writeGenericValue(analyticsReport.getTenantAnalysis());
            out.writeGenericValue(analyticsReport.getTrendAnalysis());
            out.writeInstant(analyticsReport.getGeneratedAt());
        } else {
            out.writeBoolean(false);
        }
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("action", action);
        builder.field("success", success);
        
        if (message != null) {
            builder.field("message", message);
        }
        
        if (metrics != null) {
            builder.startObject("metrics");
            builder.field("total_requests", metrics.getTotalRequests());
            builder.field("allowed_requests", metrics.getAllowedRequests());
            builder.field("denied_requests", metrics.getDeniedRequests());
            builder.field("error_requests", metrics.getErrorRequests());
            builder.field("allow_rate", metrics.getAllowRate());
            builder.field("deny_rate", metrics.getDenyRate());
            builder.field("error_rate", metrics.getErrorRate());
            builder.field("timestamp", metrics.getTimestamp().toString());
            
            if (!metrics.getActionMetrics().isEmpty()) {
                builder.field("top_actions", metrics.getActionMetrics());
            }
            
            if (!metrics.getTenantMetrics().isEmpty()) {
                builder.field("top_tenants", metrics.getTenantMetrics());
            }
            
            if (!metrics.getUserMetrics().isEmpty()) {
                builder.field("top_users", metrics.getUserMetrics());
            }
            
            builder.endObject();
        }
        
        if (analyticsReport != null) {
            builder.startObject("analytics");
            builder.field("threat_score", analyticsReport.getThreatScore());
            builder.field("threat_level", analyticsReport.getThreatLevel());
            builder.field("requires_immediate_action", analyticsReport.requiresImmediateAction());
            builder.field("performance_status", analyticsReport.getPerformanceStatus());
            builder.field("suspicious_user_count", analyticsReport.getSuspiciousUserCount());
            builder.field("average_success_rate", analyticsReport.getAverageSuccessRate());
            builder.field("summary", analyticsReport.getSummary());
            builder.field("generated_at", analyticsReport.getGeneratedAt().toString());
            
            if (!analyticsReport.getPerformanceAnalysis().isEmpty()) {
                builder.field("performance_analysis", analyticsReport.getPerformanceAnalysis());
            }
            
            if (!analyticsReport.getUserBehaviorAnalysis().isEmpty()) {
                builder.field("user_behavior_analysis", analyticsReport.getUserBehaviorAnalysis());
            }
            
            if (!analyticsReport.getTenantAnalysis().isEmpty()) {
                builder.field("tenant_analysis", analyticsReport.getTenantAnalysis());
            }
            
            if (!analyticsReport.getTrendAnalysis().isEmpty()) {
                builder.field("trend_analysis", analyticsReport.getTrendAnalysis());
            }
            
            builder.endObject();
        }
        
        builder.endObject();
        return builder;
    }
    
    // Getters
    public String getAction() { return action; }
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public AuditMetrics getMetrics() { return metrics; }
    public AnalyticsReport getAnalyticsReport() { return analyticsReport; }
}