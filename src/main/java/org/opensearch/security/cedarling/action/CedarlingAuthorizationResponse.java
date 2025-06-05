package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response from Cedarling authorization request
 */
public class CedarlingAuthorizationResponse extends ActionResponse implements ToXContentObject {
    
    private boolean allowed;
    private String reason;
    private String diagnostics;
    
    public CedarlingAuthorizationResponse() {}
    
    public CedarlingAuthorizationResponse(boolean allowed, String reason, String diagnostics) {
        this.allowed = allowed;
        this.reason = reason;
        this.diagnostics = diagnostics;
    }
    
    public CedarlingAuthorizationResponse(StreamInput in) throws IOException {
        super(in);
        this.allowed = in.readBoolean();
        this.reason = in.readOptionalString();
        this.diagnostics = in.readOptionalString();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(allowed);
        out.writeOptionalString(reason);
        out.writeOptionalString(diagnostics);
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("allowed", allowed);
        if (reason != null) {
            builder.field("reason", reason);
        }
        if (diagnostics != null) {
            builder.field("diagnostics", diagnostics);
        }
        builder.endObject();
        return builder;
    }
    
    // Getters
    public boolean isAllowed() { return allowed; }
    public String getReason() { return reason; }
    public String getDiagnostics() { return diagnostics; }
}