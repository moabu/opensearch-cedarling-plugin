package org.opensearch.security.cedarling.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Complete snapshot of the Cedar policy store
 * 
 * Contains all policies, schema definitions, and metadata
 * needed for local policy evaluation and caching.
 */
public class PolicyStoreSnapshot {
    
    @JsonProperty("version")
    private String version;
    
    @JsonProperty("last_modified")
    private String lastModified;
    
    @JsonProperty("policies")
    private List<CedarPolicy> policies;
    
    @JsonProperty("schema")
    private CedarSchema schema;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    public PolicyStoreSnapshot() {}
    
    public PolicyStoreSnapshot(String version, String lastModified, List<CedarPolicy> policies, 
                              CedarSchema schema, Map<String, Object> metadata) {
        this.version = version;
        this.lastModified = lastModified;
        this.policies = policies;
        this.schema = schema;
        this.metadata = metadata;
    }
    
    // Getters and setters
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    
    public String getLastModified() { return lastModified; }
    public void setLastModified(String lastModified) { this.lastModified = lastModified; }
    
    public List<CedarPolicy> getPolicies() { return policies; }
    public void setPolicies(List<CedarPolicy> policies) { this.policies = policies; }
    
    public CedarSchema getSchema() { return schema; }
    public void setSchema(CedarSchema schema) { this.schema = schema; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    /**
     * Individual Cedar policy
     */
    public static class CedarPolicy {
        
        @JsonProperty("id")
        private String id;
        
        @JsonProperty("content")
        private String content;
        
        @JsonProperty("description")
        private String description;
        
        @JsonProperty("effect")
        private String effect; // permit or forbid
        
        @JsonProperty("created_at")
        private String createdAt;
        
        @JsonProperty("updated_at")
        private String updatedAt;
        
        @JsonProperty("tags")
        private List<String> tags;
        
        public CedarPolicy() {}
        
        public CedarPolicy(String id, String content, String description, String effect) {
            this.id = id;
            this.content = content;
            this.description = description;
            this.effect = effect;
        }
        
        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public String getEffect() { return effect; }
        public void setEffect(String effect) { this.effect = effect; }
        
        public String getCreatedAt() { return createdAt; }
        public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
        
        public String getUpdatedAt() { return updatedAt; }
        public void setUpdatedAt(String updatedAt) { this.updatedAt = updatedAt; }
        
        public List<String> getTags() { return tags; }
        public void setTags(List<String> tags) { this.tags = tags; }
        
        @Override
        public String toString() {
            return String.format("CedarPolicy{id='%s', effect='%s', description='%s'}", 
                               id, effect, description);
        }
    }
    
    /**
     * Cedar schema definition
     */
    public static class CedarSchema {
        
        @JsonProperty("entities")
        private Map<String, EntityType> entities;
        
        @JsonProperty("actions")
        private Map<String, ActionType> actions;
        
        @JsonProperty("common_types")
        private Map<String, Object> commonTypes;
        
        public CedarSchema() {}
        
        public Map<String, EntityType> getEntities() { return entities; }
        public void setEntities(Map<String, EntityType> entities) { this.entities = entities; }
        
        public Map<String, ActionType> getActions() { return actions; }
        public void setActions(Map<String, ActionType> actions) { this.actions = actions; }
        
        public Map<String, Object> getCommonTypes() { return commonTypes; }
        public void setCommonTypes(Map<String, Object> commonTypes) { this.commonTypes = commonTypes; }
        
        /**
         * Entity type definition
         */
        public static class EntityType {
            
            @JsonProperty("attributes")
            private Map<String, Object> attributes;
            
            @JsonProperty("parents")
            private List<String> parents;
            
            public EntityType() {}
            
            public Map<String, Object> getAttributes() { return attributes; }
            public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }
            
            public List<String> getParents() { return parents; }
            public void setParents(List<String> parents) { this.parents = parents; }
        }
        
        /**
         * Action type definition
         */
        public static class ActionType {
            
            @JsonProperty("applies_to")
            private AppliesTo appliesTo;
            
            @JsonProperty("member_of")
            private List<String> memberOf;
            
            public ActionType() {}
            
            public AppliesTo getAppliesTo() { return appliesTo; }
            public void setAppliesTo(AppliesTo appliesTo) { this.appliesTo = appliesTo; }
            
            public List<String> getMemberOf() { return memberOf; }
            public void setMemberOf(List<String> memberOf) { this.memberOf = memberOf; }
            
            /**
             * Defines what entities an action applies to
             */
            public static class AppliesTo {
                
                @JsonProperty("principal_types")
                private List<String> principalTypes;
                
                @JsonProperty("resource_types")
                private List<String> resourceTypes;
                
                @JsonProperty("context")
                private Map<String, Object> context;
                
                public AppliesTo() {}
                
                public List<String> getPrincipalTypes() { return principalTypes; }
                public void setPrincipalTypes(List<String> principalTypes) { this.principalTypes = principalTypes; }
                
                public List<String> getResourceTypes() { return resourceTypes; }
                public void setResourceTypes(List<String> resourceTypes) { this.resourceTypes = resourceTypes; }
                
                public Map<String, Object> getContext() { return context; }
                public void setContext(Map<String, Object> context) { this.context = context; }
            }
        }
    }
    
    @Override
    public String toString() {
        return String.format("PolicyStoreSnapshot{version='%s', policies=%d, lastModified='%s'}", 
                           version, policies != null ? policies.size() : 0, lastModified);
    }
}