package org.opensearch.security.cedarling.tbac;

import java.util.*;

/**
 * Represents TBAC tokens extracted from the OpenSearch query ext object
 * 
 * This class handles the authentication tokens passed through the ext object
 * for Token-Based Access Control (TBAC) evaluation.
 */
public class TBACTokens {
    
    private final String accessToken;
    private final String idToken;
    private final String userId;
    private final String tenantId;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> claims;
    
    public TBACTokens() {
        this(null, null, null, null, new HashSet<>(), new HashSet<>(), new HashMap<>());
    }
    
    public TBACTokens(String accessToken, String idToken, String userId, String tenantId,
                     Set<String> roles, Set<String> permissions, Map<String, Object> claims) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.userId = userId;
        this.tenantId = tenantId;
        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
        this.permissions = permissions != null ? new HashSet<>(permissions) : new HashSet<>();
        this.claims = claims != null ? new HashMap<>(claims) : new HashMap<>();
    }
    
    /**
     * Creates TBACTokens from a map extracted from the ext object
     */
    public static TBACTokens fromMap(Map<String, Object> tokensMap) {
        String accessToken = (String) tokensMap.get("access_token");
        String idToken = (String) tokensMap.get("id_token");
        String userId = (String) tokensMap.get("user_id");
        String tenantId = (String) tokensMap.get("tenant_id");
        
        Set<String> roles = new HashSet<>();
        Object rolesObj = tokensMap.get("roles");
        if (rolesObj instanceof List) {
            for (Object role : (List<?>) rolesObj) {
                if (role instanceof String) {
                    roles.add((String) role);
                }
            }
        }
        
        Set<String> permissions = new HashSet<>();
        Object permissionsObj = tokensMap.get("permissions");
        if (permissionsObj instanceof List) {
            for (Object permission : (List<?>) permissionsObj) {
                if (permission instanceof String) {
                    permissions.add((String) permission);
                }
            }
        }
        
        Map<String, Object> claims = new HashMap<>();
        Object claimsObj = tokensMap.get("claims");
        if (claimsObj instanceof Map) {
            claims.putAll((Map<String, Object>) claimsObj);
        }
        
        return new TBACTokens(accessToken, idToken, userId, tenantId, roles, permissions, claims);
    }
    
    public boolean hasAccessToken() {
        return accessToken != null && !accessToken.isEmpty();
    }
    
    public boolean hasIdToken() {
        return idToken != null && !idToken.isEmpty();
    }
    
    public String getAccessToken() {
        return accessToken;
    }
    
    public String getIdToken() {
        return idToken;
    }
    
    public String getUserId() {
        return userId;
    }
    
    public String getTenantId() {
        return tenantId;
    }
    
    public Set<String> getRoles() {
        return new HashSet<>(roles);
    }
    
    public Set<String> getPermissions() {
        return new HashSet<>(permissions);
    }
    
    public Map<String, Object> getClaims() {
        return new HashMap<>(claims);
    }
    
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
    
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }
    
    public Object getClaim(String claimName) {
        return claims.get(claimName);
    }
}