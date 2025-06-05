package org.opensearch.security.cedarling;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.security.cedarling.action.CedarlingAuthorizationAction;
import org.opensearch.security.cedarling.action.CedarlingAuditAction;
import org.opensearch.security.cedarling.action.CedarlingPolicyAction;
import org.opensearch.security.cedarling.action.CedarlingPolicySyncAction;
import org.opensearch.security.cedarling.action.TransportCedarlingAuthorizationAction;
import org.opensearch.security.cedarling.action.TransportCedarlingAuditAction;
import org.opensearch.security.cedarling.action.TransportCedarlingPolicyAction;
import org.opensearch.security.cedarling.action.TransportCedarlingPolicySyncAction;
import org.opensearch.security.cedarling.rest.RestCedarlingAuthorizationHandler;
import org.opensearch.security.cedarling.rest.RestCedarlingAuditHandler;
import org.opensearch.security.cedarling.rest.RestCedarlingPolicyHandler;
import org.opensearch.security.cedarling.rest.RestCedarlingPolicySyncHandler;
import org.opensearch.security.cedarling.rest.RestCedarlingStatusHandler;
import org.opensearch.security.cedarling.rest.RestCedarlingPolicyInterfaceHandler;
import org.opensearch.security.cedarling.rest.PolicyDashboardRestHandler;
import org.opensearch.security.cedarling.rest.AuditAnalyticsRestHandler;
import org.opensearch.security.cedarling.rest.RestDataBasedAuthorizationHandler;
import org.opensearch.security.cedarling.rest.RestSchemaManagementHandler;
import org.opensearch.security.cedarling.rest.RestTBACDemoHandler;
import org.opensearch.security.cedarling.rest.RestDataPolicyAuthorizationHandler;
import org.opensearch.security.cedarling.audit.CedarlingAuditLogger;
import org.opensearch.security.cedarling.audit.AuditLogger;
import org.opensearch.security.cedarling.filter.CedarlingSecurityFilter;
import org.opensearch.security.cedarling.filter.PostQueryCedarlingFilter;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.service.EmbeddedCedarlingService;
import org.opensearch.security.cedarling.service.PolicyDecisionTracker;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

/**
 * OpenSearch Security Plugin with Cedarling Integration
 * 
 * This plugin extends OpenSearch's security capabilities by integrating with
 * the Cedarling policy decision point for fine-grained access control.
 * 
 * Key Features:
 * - Token-based access control (TBAC) using Cedar policies
 * - Real-time policy evaluation for index and document-level security
 * - Integration with Janssen Project Cedarling service
 * - Multi-tenant data isolation with account-level granularity
 * - Audit logging for all authorization decisions
 */
public class CedarlingSecurityPlugin extends Plugin implements ActionPlugin {

    public static final String PLUGIN_NAME = "cedarling-security";
    
    // Plugin settings
    public static final Setting<String> CEDARLING_POLICY_STORE_ID = Setting.simpleString(
        "cedarling.policy_store_id",
        "opensearch-security-store",
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    public static final Setting<Boolean> CEDARLING_ENABLED = Setting.boolSetting(
        "cedarling.enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    public static final Setting<Integer> CEDARLING_TIMEOUT_MS = Setting.intSetting(
        "cedarling.timeout_ms",
        5000,
        1000,
        30000,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    public static final Setting<Boolean> CEDARLING_AUDIT_ENABLED = Setting.boolSetting(
        "cedarling.audit.enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    // Live synchronization settings
    public static final Setting<Boolean> CEDARLING_SYNC_ENABLED = Setting.boolSetting(
        "cedarling.sync.enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    public static final Setting<Long> CEDARLING_SYNC_INTERVAL_SECONDS = Setting.longSetting(
        "cedarling.sync.interval_seconds",
        30L,
        5L,
        3600L,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    // Audit and analytics settings
    public static final Setting<Boolean> CEDARLING_AUDIT_METRICS_ENABLED = Setting.boolSetting(
        "cedarling.audit.metrics.enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );
    
    public static final Setting<Boolean> CEDARLING_AUDIT_ANALYTICS_ENABLED = Setting.boolSetting(
        "cedarling.audit.analytics.enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    private CedarlingService cedarlingService;
    private PolicyStoreSynchronizer policyStoreSynchronizer;
    private CedarlingAuditLogger auditLogger;
    private AuditLogger standardAuditLogger;
    private PolicyDecisionTracker policyDecisionTracker;
    private CedarlingSecurityFilter securityFilter;
    private PostQueryCedarlingFilter postQueryFilter;

    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        Settings settings = clusterService.getSettings();
        this.cedarlingService = new CedarlingService(settings, threadPool);
        
        // Initialize policy decision tracker for dashboard visualization
        this.policyDecisionTracker = new PolicyDecisionTracker(settings);
        
        // Initialize comprehensive audit logging system
        this.auditLogger = new CedarlingAuditLogger(settings, threadPool);
        this.standardAuditLogger = new AuditLogger(settings, threadPool);
        
        // Initialize security filters for pre-query and post-query enforcement
        this.securityFilter = new CedarlingSecurityFilter(
            cedarlingService, 
            threadPool.getThreadContext(), 
            standardAuditLogger,
            null // AuditAnalytics will be injected later
        );
        
        this.postQueryFilter = new PostQueryCedarlingFilter(
            cedarlingService,
            threadPool.getThreadContext(),
            standardAuditLogger
        );
        
        // Initialize enhanced policy store synchronizer if enabled
        if (CEDARLING_SYNC_ENABLED.get(settings)) {
            this.policyStoreSynchronizer = new PolicyStoreSynchronizer(
                settings, 
                threadPool, 
                cedarlingService,
                clusterService,
                cedarlingService.getHttpClient()
            );
            // Start enhanced synchronization with intelligent strategies
            policyStoreSynchronizer.start();
        }
        
        return Arrays.asList(cedarlingService, policyDecisionTracker, policyStoreSynchronizer, 
                           auditLogger, standardAuditLogger, securityFilter, postQueryFilter);
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return Arrays.asList(
            new ActionHandler<>(CedarlingAuthorizationAction.INSTANCE, TransportCedarlingAuthorizationAction.class),
            new ActionHandler<>(CedarlingPolicyAction.INSTANCE, TransportCedarlingPolicyAction.class),
            new ActionHandler<>(CedarlingPolicySyncAction.INSTANCE, TransportCedarlingPolicySyncAction.class),
            new ActionHandler<>(CedarlingAuditAction.INSTANCE, TransportCedarlingAuditAction.class)
        );
    }

    @Override
    public List<ActionFilter> getActionFilters() {
        // Register both pre-query and post-query Cedar policy enforcement filters
        return Arrays.asList(securityFilter, postQueryFilter);
    }

    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return Arrays.asList(
            new RestCedarlingAuthorizationHandler(),
            new RestCedarlingPolicyHandler(),
            new RestCedarlingPolicySyncHandler(),
            new RestCedarlingAuditHandler(),
            new RestCedarlingStatusHandler(),
            new RestCedarlingPolicyInterfaceHandler(),
            new PolicyDashboardRestHandler(new EmbeddedCedarlingService(settings, threadPool, auditLogger), policyDecisionTracker),
            new AuditAnalyticsRestHandler(auditLogger),
            new RestDataBasedAuthorizationHandler(cedarlingService, standardAuditLogger),
            new RestSchemaManagementHandler(cedarlingService, standardAuditLogger),
            new RestTBACDemoHandler(new CedarlingClient(settings)),
            new RestDataPolicyAuthorizationHandler(new CedarlingClient(settings), standardAuditLogger)
        );
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
            CEDARLING_POLICY_STORE_ID,
            CEDARLING_ENABLED,
            CEDARLING_TIMEOUT_MS,
            CEDARLING_AUDIT_ENABLED,
            CEDARLING_SYNC_ENABLED,
            CEDARLING_SYNC_INTERVAL_SECONDS,
            CEDARLING_AUDIT_METRICS_ENABLED,
            CEDARLING_AUDIT_ANALYTICS_ENABLED
        );
    }

    @Override
    public String getFeatureName() {
        return PLUGIN_NAME;
    }

    @Override
    public String getFeatureDescription() {
        return "OpenSearch Security Plugin with Cedarling Integration for Fine-Grained Access Control";
    }
    
    @Override
    public void close() {
        if (policyStoreSynchronizer != null) {
            policyStoreSynchronizer.stop();
        }
        if (cedarlingService != null) {
            cedarlingService.close();
        }
    }
}