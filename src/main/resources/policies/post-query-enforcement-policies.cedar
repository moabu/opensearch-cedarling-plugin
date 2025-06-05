// Cedar Policies for Post-Query Enforcement
// These policies are applied after OpenSearch returns results to filter documents and fields

// Document-level access control based on classification
permit(
    principal == User::"admin",
    action == ViewDocument,
    resource
) when {
    true // Admin can view all documents
};

permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.classification == "public" ||
    (resource.classification == "internal" && principal.clearance_level in ["internal", "confidential", "secret"]) ||
    (resource.classification == "confidential" && principal.clearance_level in ["confidential", "secret"]) ||
    (resource.classification == "secret" && principal.clearance_level == "secret")
};

// Field-level access control
permit(
    principal is User,
    action == ViewDocumentFields,
    resource is Document
) when {
    principal.clearance_level == "secret"
} unless {
    context.restricted_fields exists
} advice {
    "field_restrictions": []
};

permit(
    principal is User,
    action == ViewDocumentFields,
    resource is Document
) when {
    principal.clearance_level == "confidential"
} advice {
    "field_restrictions": ["salary", "ssn", "personal_details"]
};

permit(
    principal is User,
    action == ViewDocumentFields,
    resource is Document
) when {
    principal.clearance_level == "internal"
} advice {
    "field_restrictions": ["salary", "ssn", "personal_details", "financial_data", "budget"]
};

permit(
    principal is User,
    action == ViewDocumentFields,
    resource is Document
) when {
    principal.clearance_level == "public"
} advice {
    "field_restrictions": ["salary", "ssn", "personal_details", "financial_data", "budget", "internal_notes", "confidential_remarks"]
};

// Content-based access control
permit(
    principal is User,
    action == AccessCategory,
    resource == DataCategory::"financial_data"
) when {
    principal.department == "finance" ||
    principal.role == "CFO" ||
    principal.role == "financial_analyst" ||
    principal.clearance_level == "secret"
};

permit(
    principal is User,
    action == AccessCategory,
    resource == DataCategory::"personal_data"
) when {
    principal.department == "hr" ||
    principal.role == "HR_manager" ||
    principal.clearance_level in ["confidential", "secret"]
};

permit(
    principal is User,
    action == AccessCategory,
    resource == DataCategory::"public_data"
) when {
    true // Everyone can access public data
};

forbid(
    principal is User,
    action == AccessCategory,
    resource == DataCategory::"restricted_data"
) unless {
    principal.clearance_level == "secret" &&
    principal.special_access == true
};

// Multi-tenant data isolation
permit(
    principal is User,
    action == AccessTenantData,
    resource is TenantDocument
) when {
    principal.tenant == context.document_tenant ||
    principal.role == "super_admin"
};

// Department-based access control
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.department == principal.department ||
    principal.cross_department_access == true
};

// Time-based access control for sensitive data
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.sensitivity_level == "high"
} unless {
    context.request_time >= datetime("2024-01-01T09:00:00Z") &&
    context.request_time <= datetime("2024-12-31T17:00:00Z")
} advice {
    "access_window": "business_hours_only"
};

// Dynamic field filtering based on user role
permit(
    principal is User,
    action == ViewDocumentFields,
    resource is Document
) when {
    principal.role == "manager"
} advice {
    "field_restrictions": 
        if resource.department == principal.department 
        then ["ssn", "personal_phone"] 
        else ["salary", "ssn", "personal_details", "performance_review"]
};

// Audit requirement for sensitive document access
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.sensitivity_level == "critical"
} advice {
    "audit_required": true,
    "justification_required": true,
    "approval_needed": principal.role != "director"
};

// Geographic data access restrictions
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.geographic_restriction exists
} unless {
    resource.geographic_restriction != principal.location &&
    principal.global_access != true
};

// Data retention and access expiry
forbid(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    context.document_age_days > 2555 && // 7 years
    resource.retention_policy == "standard" &&
    principal.archival_access != true
};

// Project-based access control
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    resource.project_id in principal.authorized_projects ||
    principal.role == "project_manager"
};

// Emergency access override
permit(
    principal is User,
    action == ViewDocument,
    resource is Document
) when {
    context.emergency_mode == true &&
    principal.emergency_access == true
} advice {
    "emergency_access_logged": true,
    "supervisor_notification": true
};