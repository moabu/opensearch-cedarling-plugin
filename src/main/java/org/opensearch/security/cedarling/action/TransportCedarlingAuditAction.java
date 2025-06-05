package org.opensearch.security.cedarling.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.cedarling.audit.AuditLogger;
import org.opensearch.security.cedarling.audit.AuditAnalytics;
import org.opensearch.security.cedarling.audit.AuditMetrics;
import org.opensearch.security.cedarling.audit.AnalyticsReport;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport handler for audit and analytics operations
 */
public class TransportCedarlingAuditAction extends HandledTransportAction<CedarlingAuditRequest, CedarlingAuditResponse> {
    
    private final AuditLogger auditLogger;
    private final AuditAnalytics auditAnalytics;
    
    @Inject
    public TransportCedarlingAuditAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AuditLogger auditLogger,
            AuditAnalytics auditAnalytics
    ) {
        super(CedarlingAuditAction.NAME, transportService, actionFilters, CedarlingAuditRequest::new);
        this.auditLogger = auditLogger;
        this.auditAnalytics = auditAnalytics;
    }
    
    @Override
    protected void doExecute(Task task, CedarlingAuditRequest request, ActionListener<CedarlingAuditResponse> listener) {
        String action = request.getAction();
        
        try {
            switch (action) {
                case "metrics":
                    handleMetricsRequest(listener);
                    break;
                case "analytics":
                    handleAnalyticsRequest(listener);
                    break;
                case "reset":
                    handleResetRequest(listener);
                    break;
                default:
                    listener.onResponse(new CedarlingAuditResponse(
                        action, 
                        false, 
                        "Unknown action: " + action
                    ));
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }
    
    private void handleMetricsRequest(ActionListener<CedarlingAuditResponse> listener) {
        if (auditLogger == null) {
            listener.onResponse(new CedarlingAuditResponse(
                "metrics",
                false,
                "Audit logging is not available"
            ));
            return;
        }
        
        AuditMetrics metrics = auditLogger.getMetrics();
        listener.onResponse(new CedarlingAuditResponse(
            "metrics",
            true,
            "Audit metrics retrieved successfully",
            metrics
        ));
    }
    
    private void handleAnalyticsRequest(ActionListener<CedarlingAuditResponse> listener) {
        if (auditAnalytics == null) {
            listener.onResponse(new CedarlingAuditResponse(
                "analytics",
                false,
                "Audit analytics is not available"
            ));
            return;
        }
        
        AnalyticsReport report = auditAnalytics.generateReport();
        listener.onResponse(new CedarlingAuditResponse(
            "analytics",
            true,
            "Analytics report generated successfully",
            report
        ));
    }
    
    private void handleResetRequest(ActionListener<CedarlingAuditResponse> listener) {
        if (auditLogger == null) {
            listener.onResponse(new CedarlingAuditResponse(
                "reset",
                false,
                "Audit logging is not available"
            ));
            return;
        }
        
        auditLogger.resetMetrics();
        listener.onResponse(new CedarlingAuditResponse(
            "reset",
            true,
            "Audit metrics reset successfully"
        ));
    }
}