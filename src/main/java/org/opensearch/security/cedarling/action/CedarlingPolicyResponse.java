package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Response from Cedarling policy management operations
 */
public class CedarlingPolicyResponse extends ActionResponse implements ToXContentObject {
    
    private boolean success;
    private String message;
    private Object data;
    
    public CedarlingPolicyResponse() {}
    
    public CedarlingPolicyResponse(boolean success, String message, Object data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }
    
    public CedarlingPolicyResponse(StreamInput in) throws IOException {
        super(in);
        this.success = in.readBoolean();
        this.message = in.readOptionalString();
        this.data = in.readGenericValue();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(success);
        out.writeOptionalString(message);
        out.writeGenericValue(data);
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("success", success);
        if (message != null) {
            builder.field("message", message);
        }
        if (data != null) {
            builder.field("data", data);
        }
        builder.endObject();
        return builder;
    }
    
    // Getters
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public Object getData() { return data; }
}