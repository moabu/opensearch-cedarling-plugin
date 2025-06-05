package org.opensearch.security.cedarling.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * AuthZen evaluation request model that matches the authentic jans-cedarling service
 * Based on the actual Cedarling Flask sidecar implementation
 */
public class AuthZenEvaluationRequest {
    
    @JsonProperty("subject")
    private Subject subject;
    
    @JsonProperty("resource")
    private Resource resource;
    
    @JsonProperty("action")
    private Action action;
    
    @JsonProperty("context")
    private Map<String, Object> context;
    
    public AuthZenEvaluationRequest() {}
    
    public AuthZenEvaluationRequest(Subject subject, Resource resource, Action action, Map<String, Object> context) {
        this.subject = subject;
        this.resource = resource;
        this.action = action;
        this.context = context;
    }
    
    // Getters and setters
    public Subject getSubject() { return subject; }
    public void setSubject(Subject subject) { this.subject = subject; }
    
    public Resource getResource() { return resource; }
    public void setResource(Resource resource) { this.resource = resource; }
    
    public Action getAction() { return action; }
    public void setAction(Action action) { this.action = action; }
    
    public Map<String, Object> getContext() { return context; }
    public void setContext(Map<String, Object> context) { this.context = context; }
    
    /**
     * Subject entity in AuthZen format
     */
    public static class Subject {
        @JsonProperty("type")
        private String type;
        
        @JsonProperty("id")
        private String id;
        
        @JsonProperty("properties")
        private Map<String, Object> properties;
        
        public Subject() {}
        
        public Subject(String type, String id, Map<String, Object> properties) {
            this.type = type;
            this.id = id;
            this.properties = properties;
        }
        
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }
    
    /**
     * Resource entity in AuthZen format
     */
    public static class Resource {
        @JsonProperty("type")
        private String type;
        
        @JsonProperty("id")
        private String id;
        
        @JsonProperty("properties")
        private Map<String, Object> properties;
        
        public Resource() {}
        
        public Resource(String type, String id, Map<String, Object> properties) {
            this.type = type;
            this.id = id;
            this.properties = properties;
        }
        
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }
    
    /**
     * Action entity in AuthZen format
     */
    public static class Action {
        @JsonProperty("name")
        private String name;
        
        @JsonProperty("properties")
        private Map<String, Object> properties;
        
        public Action() {}
        
        public Action(String name, Map<String, Object> properties) {
            this.name = name;
            this.properties = properties;
        }
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }
}