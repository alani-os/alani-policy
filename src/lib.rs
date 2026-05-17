#![cfg_attr(not(feature = "std"), no_std)]

//! Dependency-free policy contracts for the Alani MVK.
//!
//! This crate owns declarative capability, access-control, sandbox, audit,
//! resource-budget, and redaction policy surfaces. Enforcement remains in
//! sibling repositories; this crate provides stable, no_std-friendly contracts
//! that can be consumed once the public API is stabilized.

pub mod capability;
pub mod evaluator;
pub mod rules;
pub mod sandbox;

pub use capability::{
    Capability, CapabilityDescriptor, CapabilityGrant, CapabilityId, CapabilityScope,
    CapabilitySet, CapabilityTable, Principal, PrincipalKind, CAP_ATTEST, CAP_AUDIT_APPEND,
    CAP_AUDIT_QUERY, CAP_AUDIT_VERIFY, CAP_CAPABILITY_ADMIN, CAP_COGNITION_INFER,
    CAP_COGNITION_MEMORY_WRITE, CAP_CONFIG_READ, CAP_CONFIG_WRITE, CAP_DEVICE_CALL,
    CAP_DEVICE_LIST, CAP_DEVICE_OPEN, CAP_MEMORY_MAP, CAP_MEMORY_SHARE, CAP_POLICY_MANAGE,
    CAP_POLICY_QUERY, CAP_RANDOM, CAP_STORAGE_READ, CAP_STORAGE_WRITE, CAP_TASK_MANAGE,
    CAP_TASK_SPAWN, CAP_TRACE_CONTEXT, KNOWN_CAPABILITY_BITS, MAX_CAPABILITY_SCOPE_LEN,
    MAX_PRINCIPAL_LABEL_LEN,
};
pub use evaluator::{
    AuditPolicyRecord, EvaluationContext, EvaluatorDescriptor, PolicyDecision, PolicyEngine,
    PolicyEvaluation, PolicyRequest, StaticPolicyEngine,
};
pub use rules::{
    OperationKind, PolicyEffect, PolicyRule, PolicyRuleSet, ResourceKind, RulesDescriptor,
    MAX_RULE_LABEL_LEN,
};
pub use sandbox::{
    SandboxDecision, SandboxDescriptor, SandboxOperation, SandboxProfile, SandboxRequest,
    SandboxResource, SandboxResourceSet, SandboxStatus, SandboxTable, KNOWN_SANDBOX_RESOURCES,
    MAX_SANDBOX_LABEL_LEN,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-policy";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["capability", "rules", "evaluator", "sandbox"];

/// Policy bundle schema version owned by this crate.
pub const POLICY_SCHEMA_VERSION: &str = "alani.policy.v1";

/// Feature bit for capability taxonomy and attenuation helpers.
pub const POLICY_FEATURE_CAPABILITIES: u64 = 1 << 0;
/// Feature bit for declarative policy rules.
pub const POLICY_FEATURE_RULES: u64 = 1 << 1;
/// Feature bit for static evaluator contracts.
pub const POLICY_FEATURE_EVALUATOR: u64 = 1 << 2;
/// Feature bit for sandbox profile contracts.
pub const POLICY_FEATURE_SANDBOX: u64 = 1 << 3;
/// Feature bit for audit decision metadata.
pub const POLICY_FEATURE_AUDIT_METADATA: u64 = 1 << 4;
/// Feature bit for data classification and redaction checks.
pub const POLICY_FEATURE_REDACTION: u64 = 1 << 5;
/// Feature bit for resource-budget checks.
pub const POLICY_FEATURE_BUDGETS: u64 = 1 << 6;

/// All feature bits known by this crate version.
pub const POLICY_KNOWN_FEATURES: u64 = POLICY_FEATURE_CAPABILITIES
    | POLICY_FEATURE_RULES
    | POLICY_FEATURE_EVALUATOR
    | POLICY_FEATURE_SANDBOX
    | POLICY_FEATURE_AUDIT_METADATA
    | POLICY_FEATURE_REDACTION
    | POLICY_FEATURE_BUDGETS;

/// Maximum generic policy label length.
pub const MAX_POLICY_LABEL_LEN: usize = 128;

/// Invalid identifier placeholder for policy records.
pub const INVALID_POLICY_ID: u64 = 0;

/// Result alias used by policy validation and evaluation APIs.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Error taxonomy for policy validation, evaluation, and sandbox checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// A required field was empty or omitted.
    MissingField,
    /// A version or schema identifier was not supported.
    InvalidVersion,
    /// A bounded string field exceeded its documented limit.
    FieldTooLong,
    /// A policy-facing label contained unsupported characters.
    InvalidLabel,
    /// Reserved feature, capability, rule, or sandbox bits were supplied.
    ReservedBits,
    /// Capability metadata failed validation.
    InvalidCapability,
    /// Required capability authority was missing.
    MissingCapability,
    /// Principal metadata failed validation.
    InvalidPrincipal,
    /// Resource metadata failed validation.
    InvalidResource,
    /// Rule metadata failed validation.
    InvalidRule,
    /// Rule or capability identifier already exists.
    Duplicate,
    /// Requested rule, grant, or sandbox profile was not found.
    NotFound,
    /// Fixed-capacity table is full.
    CapacityExceeded,
    /// Evaluation denied the request.
    PolicyDenied,
    /// Evaluation requires operator or higher-layer escalation.
    EscalationRequired,
    /// Operation requires durable audit evidence.
    AuditRequired,
    /// Resource budget metadata is malformed.
    InvalidBudget,
    /// Request exceeded its declared deadline.
    DeadlineExceeded,
    /// Trace identifiers are malformed.
    InvalidTrace,
    /// Data classification and redaction state are incompatible.
    InvalidRedaction,
    /// Sandbox profile denied the operation.
    SandboxViolation,
    /// Internal invariant failed.
    Internal,
}

impl PolicyError {
    /// Stable reason label for diagnostics, audit records, and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::InvalidVersion => "invalid_version",
            Self::FieldTooLong => "field_too_long",
            Self::InvalidLabel => "invalid_label",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidCapability => "invalid_capability",
            Self::MissingCapability => "missing_capability",
            Self::InvalidPrincipal => "invalid_principal",
            Self::InvalidResource => "invalid_resource",
            Self::InvalidRule => "invalid_rule",
            Self::Duplicate => "duplicate",
            Self::NotFound => "not_found",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::PolicyDenied => "policy_denied",
            Self::EscalationRequired => "escalation_required",
            Self::AuditRequired => "audit_required",
            Self::InvalidBudget => "invalid_budget",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidRedaction => "invalid_redaction",
            Self::SandboxViolation => "sandbox_violation",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when this error represents a fail-closed security path.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::InvalidVersion
                | Self::InvalidLabel
                | Self::InvalidCapability
                | Self::MissingCapability
                | Self::InvalidPrincipal
                | Self::InvalidResource
                | Self::InvalidRule
                | Self::PolicyDenied
                | Self::EscalationRequired
                | Self::AuditRequired
                | Self::DeadlineExceeded
                | Self::InvalidTrace
                | Self::InvalidRedaction
                | Self::SandboxViolation
        )
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Stable trace context copied from observability or syscall layers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace identifier shared across component boundaries.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
}

impl TraceContext {
    /// Empty trace context used when no trace is available.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
    };

    /// Creates a trace context from stable identifiers.
    pub const fn new(trace_id: u64, span_id: u64) -> Self {
        Self { trace_id, span_id }
    }

    /// Returns `true` when both trace and span identifiers are present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates that trace identifiers are both present or both absent.
    pub const fn validate(self) -> PolicyResult<()> {
        if (self.trace_id == 0) != (self.span_id == 0) {
            Err(PolicyError::InvalidTrace)
        } else {
            Ok(())
        }
    }
}

/// Data sensitivity classification used by diagnostics and audit metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Public metadata.
    Public = 0,
    /// Operational metadata suitable for trusted operators.
    Operational = 1,
    /// Sensitive metadata requiring redaction before broad export.
    Sensitive = 2,
    /// Secret metadata that must never be exported in raw form.
    Secret = 3,
}

impl DataClass {
    /// Stable data class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }

    /// Returns `true` when broad export requires redaction.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}

/// Redaction state for policy diagnostics and audit metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// Metadata is public.
    Public = 0,
    /// Metadata is operational.
    Operational = 1,
    /// Sensitive fields were redacted.
    SensitiveRedacted = 2,
    /// Secret fields were redacted.
    SecretRedacted = 3,
    /// Sensitive fields are present and must not be exported broadly.
    UnredactedSensitive = 4,
}

impl RedactionState {
    /// Stable redaction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::SensitiveRedacted => "sensitive_redacted",
            Self::SecretRedacted => "secret_redacted",
            Self::UnredactedSensitive => "unredacted_sensitive",
        }
    }
}

/// Validates that a data class has an acceptable redaction state.
pub const fn validate_redaction(
    data_class: DataClass,
    redaction: RedactionState,
) -> PolicyResult<()> {
    match data_class {
        DataClass::Public => {
            if matches!(redaction, RedactionState::Public) {
                Ok(())
            } else {
                Err(PolicyError::InvalidRedaction)
            }
        }
        DataClass::Operational => {
            if matches!(
                redaction,
                RedactionState::Operational | RedactionState::Public
            ) {
                Ok(())
            } else {
                Err(PolicyError::InvalidRedaction)
            }
        }
        DataClass::Sensitive => {
            if matches!(redaction, RedactionState::SensitiveRedacted) {
                Ok(())
            } else {
                Err(PolicyError::InvalidRedaction)
            }
        }
        DataClass::Secret => {
            if matches!(redaction, RedactionState::SecretRedacted) {
                Ok(())
            } else {
                Err(PolicyError::InvalidRedaction)
            }
        }
    }
}

/// Validates a policy-facing label.
pub const fn validate_policy_label(label: &str, max_len: usize) -> PolicyResult<()> {
    if label.is_empty() {
        return Err(PolicyError::MissingField);
    }
    if label.len() > max_len {
        return Err(PolicyError::FieldTooLong);
    }
    let bytes = label.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !is_policy_label_byte(bytes[index]) {
            return Err(PolicyError::InvalidLabel);
        }
        index += 1;
    }
    Ok(())
}

const fn is_policy_label_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b':'
            | b'_'
            | b'*'
            | b'.'
            | b'-'
            | b'/'
            | b'@'
    )
}

/// Resource budget supplied to policy and sandbox checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBudget {
    /// Maximum compute units. Zero means unspecified or unbounded.
    pub max_compute_units: u64,
    /// Maximum memory bytes. Zero means unspecified or unbounded.
    pub max_memory_bytes: u64,
    /// Absolute monotonic deadline in nanoseconds. Zero means no deadline.
    pub deadline_ns: u64,
}

impl PolicyBudget {
    /// Unbounded budget used by permissive host-mode skeletons.
    pub const UNBOUNDED: Self = Self {
        max_compute_units: 0,
        max_memory_bytes: 0,
        deadline_ns: 0,
    };

    /// Creates an unbounded budget.
    pub const fn unbounded() -> Self {
        Self::UNBOUNDED
    }

    /// Creates a bounded budget.
    pub const fn bounded(max_compute_units: u64, max_memory_bytes: u64, deadline_ns: u64) -> Self {
        Self {
            max_compute_units,
            max_memory_bytes,
            deadline_ns,
        }
    }

    /// Returns `true` when no budget fields are constrained.
    pub const fn is_unbounded(self) -> bool {
        self.max_compute_units == 0 && self.max_memory_bytes == 0 && self.deadline_ns == 0
    }

    /// Validates internal budget field combinations.
    pub const fn validate(self) -> PolicyResult<()> {
        if self.deadline_ns != 0 && self.max_compute_units == 0 && self.max_memory_bytes == 0 {
            return Err(PolicyError::InvalidBudget);
        }
        Ok(())
    }

    /// Returns `true` when this budget permits the requested budget.
    pub const fn allows(self, requested: Self) -> bool {
        if self.max_compute_units != 0
            && (requested.max_compute_units == 0
                || requested.max_compute_units > self.max_compute_units)
        {
            return false;
        }
        if self.max_memory_bytes != 0
            && (requested.max_memory_bytes == 0
                || requested.max_memory_bytes > self.max_memory_bytes)
        {
            return false;
        }
        if self.deadline_ns != 0
            && (requested.deadline_ns == 0 || requested.deadline_ns > self.deadline_ns)
        {
            return false;
        }
        true
    }

    /// Returns `true` when the supplied monotonic timestamp is within deadline.
    pub const fn within_deadline(self, monotonic_ns: u64) -> bool {
        self.deadline_ns == 0 || monotonic_ns <= self.deadline_ns
    }
}

impl Default for PolicyBudget {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

/// Compact root view of the policy crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Policy bundle schema version.
    pub schema_version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Known capability bits.
    pub capability_bits: u64,
    /// Maximum policy label length.
    pub max_label_len: usize,
}

impl PolicyCatalog {
    /// Current policy catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        schema_version: POLICY_SCHEMA_VERSION,
        features: POLICY_KNOWN_FEATURES,
        capability_bits: KNOWN_CAPABILITY_BITS,
        max_label_len: MAX_POLICY_LABEL_LEN,
    };

    /// Returns the current policy catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Validates catalog metadata.
    pub const fn validate(self) -> PolicyResult<()> {
        if self.repository.is_empty() || self.version.is_empty() || self.schema_version.is_empty() {
            return Err(PolicyError::MissingField);
        }
        if self.features & !POLICY_KNOWN_FEATURES != 0 {
            return Err(PolicyError::ReservedBits);
        }
        if self.capability_bits & !KNOWN_CAPABILITY_BITS != 0 {
            return Err(PolicyError::ReservedBits);
        }
        if self.max_label_len == 0 {
            return Err(PolicyError::InvalidRule);
        }
        Ok(())
    }
}

/// Current policy catalog.
pub const POLICY_CATALOG: PolicyCatalog = PolicyCatalog::CURRENT;

/// Returns the current policy catalog.
pub const fn policy_catalog() -> PolicyCatalog {
    PolicyCatalog::CURRENT
}

/// Borrowed policy bundle matching the `alani.policy.v1` JSON schema shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBundle<'a> {
    /// Policy bundle schema version.
    pub schema_version: &'a str,
    /// Stable bundle label.
    pub bundle: &'a str,
    /// Monotonic bundle generation. Zero is invalid.
    pub generation: u64,
    /// Declarative policy rules.
    pub rules: &'a [rules::PolicyRule<'a>],
    /// Sandbox profiles included in the bundle.
    pub sandbox_profiles: &'a [sandbox::SandboxProfile<'a>],
}

impl<'a> PolicyBundle<'a> {
    /// Creates a policy bundle using the current schema version.
    pub const fn new(
        bundle: &'a str,
        generation: u64,
        rules: &'a [rules::PolicyRule<'a>],
        sandbox_profiles: &'a [sandbox::SandboxProfile<'a>],
    ) -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            bundle,
            generation,
            rules,
            sandbox_profiles,
        }
    }

    /// Overrides the schema version for compatibility tests.
    pub const fn with_schema_version(mut self, schema_version: &'a str) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Returns a compact summary for release evidence or diagnostics.
    pub fn summary(self) -> PolicyBundleSummary<'a> {
        PolicyBundleSummary {
            schema_version: self.schema_version,
            bundle: self.bundle,
            generation: self.generation,
            rule_count: self.rules.len(),
            sandbox_profile_count: self.sandbox_profiles.len(),
            features: POLICY_KNOWN_FEATURES,
        }
    }

    /// Validates schema identity, bundle metadata, rules, profiles, and duplicate ids.
    pub fn validate(self) -> PolicyResult<()> {
        if self.schema_version.as_bytes() != POLICY_SCHEMA_VERSION.as_bytes() {
            return Err(PolicyError::InvalidVersion);
        }
        validate_policy_label(self.bundle, MAX_POLICY_LABEL_LEN)?;
        if self.generation == 0 || self.rules.is_empty() {
            return Err(PolicyError::MissingField);
        }

        let mut rule_index = 0;
        while rule_index < self.rules.len() {
            let rule = self.rules[rule_index];
            rule.validate()?;
            let mut previous = 0;
            while previous < rule_index {
                if self.rules[previous].id == rule.id {
                    return Err(PolicyError::Duplicate);
                }
                previous += 1;
            }
            rule_index += 1;
        }

        let mut profile_index = 0;
        while profile_index < self.sandbox_profiles.len() {
            let profile = self.sandbox_profiles[profile_index];
            profile.validate()?;
            let mut previous = 0;
            while previous < profile_index {
                if self.sandbox_profiles[previous].id == profile.id {
                    return Err(PolicyError::Duplicate);
                }
                previous += 1;
            }
            profile_index += 1;
        }

        Ok(())
    }
}

/// Compact policy bundle metadata for diagnostics and release evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBundleSummary<'a> {
    /// Policy bundle schema version.
    pub schema_version: &'a str,
    /// Stable bundle label.
    pub bundle: &'a str,
    /// Monotonic bundle generation.
    pub generation: u64,
    /// Number of policy rules.
    pub rule_count: usize,
    /// Number of sandbox profiles.
    pub sandbox_profile_count: usize,
    /// Policy feature bitmap.
    pub features: u64,
}

impl<'a> PolicyBundleSummary<'a> {
    /// Validates summary metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.schema_version.as_bytes() != POLICY_SCHEMA_VERSION.as_bytes() {
            return Err(PolicyError::InvalidVersion);
        }
        if self.generation == 0 || self.rule_count == 0 {
            return Err(PolicyError::MissingField);
        }
        if self.features & !POLICY_KNOWN_FEATURES != 0 {
            return Err(PolicyError::ReservedBits);
        }
        Ok(())
    }
}
