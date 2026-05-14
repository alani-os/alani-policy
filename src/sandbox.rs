//! Sandbox profile contracts for agent and service isolation.
//!
//! Sandboxes model the policy side of isolation. They describe which resource
//! classes a principal may touch, the capabilities needed for those touches,
//! and the budget/redaction metadata enforcement layers must preserve.

use crate::capability::{
    CapabilitySet, Principal, PrincipalKind, CAP_AUDIT_APPEND, CAP_AUDIT_QUERY,
    CAP_COGNITION_INFER, CAP_CONFIG_READ, CAP_CONFIG_WRITE, CAP_DEVICE_CALL, CAP_DEVICE_OPEN,
    CAP_MEMORY_MAP, CAP_MEMORY_SHARE, CAP_POLICY_QUERY, CAP_STORAGE_READ, CAP_STORAGE_WRITE,
    CAP_TASK_MANAGE, CAP_TRACE_CONTEXT,
};
use crate::{
    validate_policy_label, validate_redaction, DataClass, PolicyBudget, PolicyError, PolicyResult,
    RedactionState, TraceContext, INVALID_POLICY_ID,
};

/// Maximum sandbox label length.
pub const MAX_SANDBOX_LABEL_LEN: usize = 96;

/// Sandbox resource bit for task/process access.
pub const SANDBOX_RESOURCE_TASK: u64 = 1 << 0;
/// Sandbox resource bit for memory access.
pub const SANDBOX_RESOURCE_MEMORY: u64 = 1 << 1;
/// Sandbox resource bit for device access.
pub const SANDBOX_RESOURCE_DEVICE: u64 = 1 << 2;
/// Sandbox resource bit for model/cognition access.
pub const SANDBOX_RESOURCE_MODEL: u64 = 1 << 3;
/// Sandbox resource bit for audit access.
pub const SANDBOX_RESOURCE_AUDIT: u64 = 1 << 4;
/// Sandbox resource bit for trace access.
pub const SANDBOX_RESOURCE_TRACE: u64 = 1 << 5;
/// Sandbox resource bit for policy access.
pub const SANDBOX_RESOURCE_POLICY: u64 = 1 << 6;
/// Sandbox resource bit for config access.
pub const SANDBOX_RESOURCE_CONFIG: u64 = 1 << 7;
/// Sandbox resource bit for storage/filesystem access.
pub const SANDBOX_RESOURCE_STORAGE: u64 = 1 << 8;
/// Sandbox resource bit for network access.
pub const SANDBOX_RESOURCE_NETWORK: u64 = 1 << 9;

/// All sandbox resource bits known by this crate version.
pub const KNOWN_SANDBOX_RESOURCES: u64 = SANDBOX_RESOURCE_TASK
    | SANDBOX_RESOURCE_MEMORY
    | SANDBOX_RESOURCE_DEVICE
    | SANDBOX_RESOURCE_MODEL
    | SANDBOX_RESOURCE_AUDIT
    | SANDBOX_RESOURCE_TRACE
    | SANDBOX_RESOURCE_POLICY
    | SANDBOX_RESOURCE_CONFIG
    | SANDBOX_RESOURCE_STORAGE
    | SANDBOX_RESOURCE_NETWORK;

/// Sandbox resource class.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxResource {
    /// Task/process resource.
    Task = 0,
    /// Memory resource.
    Memory = 1,
    /// Device resource.
    Device = 2,
    /// Model/cognition resource.
    Model = 3,
    /// Audit resource.
    Audit = 4,
    /// Trace resource.
    Trace = 5,
    /// Policy resource.
    Policy = 6,
    /// Config resource.
    Config = 7,
    /// Storage/filesystem resource.
    Storage = 8,
    /// Network resource.
    Network = 9,
}

impl SandboxResource {
    /// Resource bit.
    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Stable resource label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Memory => "memory",
            Self::Device => "device",
            Self::Model => "model",
            Self::Audit => "audit",
            Self::Trace => "trace",
            Self::Policy => "policy",
            Self::Config => "config",
            Self::Storage => "storage",
            Self::Network => "network",
        }
    }

    /// Returns `true` when access should be audit critical.
    pub const fn is_sensitive_boundary(self) -> bool {
        matches!(
            self,
            Self::Memory
                | Self::Device
                | Self::Model
                | Self::Audit
                | Self::Policy
                | Self::Config
                | Self::Storage
        )
    }
}

/// Sandbox operation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxOperation {
    /// Read or inspect.
    Read = 1,
    /// Write or mutate.
    Write = 2,
    /// Open a handle.
    Open = 3,
    /// Call a handle.
    Call = 4,
    /// Execute a task/action.
    Execute = 5,
    /// Invoke inference.
    Infer = 6,
    /// Append evidence.
    Append = 7,
    /// Query records.
    Query = 8,
    /// Administrative operation.
    Admin = 9,
}

impl SandboxOperation {
    /// Stable operation label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Call => "call",
            Self::Execute => "execute",
            Self::Infer => "infer",
            Self::Append => "append",
            Self::Query => "query",
            Self::Admin => "admin",
        }
    }
}

/// Sandbox resource bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SandboxResourceSet {
    bits: u64,
}

impl SandboxResourceSet {
    /// Empty resource set.
    pub const EMPTY: Self = Self { bits: 0 };

    /// All known sandbox resources.
    pub const ALL: Self = Self {
        bits: KNOWN_SANDBOX_RESOURCES,
    };

    /// Creates a singleton resource set.
    pub const fn single(resource: SandboxResource) -> Self {
        Self {
            bits: resource.bit(),
        }
    }

    /// Creates a set from raw bits.
    pub const fn from_bits(bits: u64) -> PolicyResult<Self> {
        if bits & !KNOWN_SANDBOX_RESOURCES != 0 {
            Err(PolicyError::ReservedBits)
        } else {
            Ok(Self { bits })
        }
    }

    /// Creates a set from known bits.
    pub const fn from_known_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns `true` when no resources are allowed.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns `true` when this set contains the resource.
    pub const fn contains(self, resource: SandboxResource) -> bool {
        self.bits & resource.bit() != 0
    }

    /// Returns the union of two resource sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}

/// Sandbox lifecycle/status.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxStatus {
    /// Sandbox enforces denials.
    Enforcing = 1,
    /// Sandbox records denials but permits execution for host-mode tuning.
    AuditOnly = 2,
    /// Sandbox is disabled and must deny by default.
    Disabled = 3,
    /// Sandbox profile is sealed and enforces denials.
    Sealed = 4,
}

impl SandboxStatus {
    /// Stable status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::AuditOnly => "audit_only",
            Self::Disabled => "disabled",
            Self::Sealed => "sealed",
        }
    }

    /// Returns `true` when denials should stop execution.
    pub const fn fail_closed(self) -> bool {
        matches!(self, Self::Enforcing | Self::Disabled | Self::Sealed)
    }
}

/// Sandbox profile applied to a principal kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxProfile<'a> {
    /// Stable profile id.
    pub id: u64,
    /// Profile label.
    pub label: &'a str,
    /// Principal kind this profile applies to.
    pub principal_kind: PrincipalKind,
    /// Allowed resource classes.
    pub allowed_resources: SandboxResourceSet,
    /// Maximum capabilities available inside the sandbox.
    pub capabilities: CapabilitySet,
    /// Maximum budget permitted inside the sandbox.
    pub max_budget: PolicyBudget,
    /// Whether trace context is mandatory.
    pub require_trace: bool,
    /// Current sandbox status.
    pub status: SandboxStatus,
    /// Whether denials should always be audited.
    pub audit_on_violation: bool,
}

impl<'a> SandboxProfile<'a> {
    /// Creates a sandbox profile.
    pub const fn new(
        id: u64,
        label: &'a str,
        principal_kind: PrincipalKind,
        allowed_resources: SandboxResourceSet,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            id,
            label,
            principal_kind,
            allowed_resources,
            capabilities,
            max_budget: PolicyBudget::UNBOUNDED,
            require_trace: false,
            status: SandboxStatus::Enforcing,
            audit_on_violation: true,
        }
    }

    /// Sets maximum budget.
    pub const fn with_max_budget(mut self, max_budget: PolicyBudget) -> Self {
        self.max_budget = max_budget;
        self
    }

    /// Requires trace context.
    pub const fn with_require_trace(mut self, require_trace: bool) -> Self {
        self.require_trace = require_trace;
        self
    }

    /// Sets status.
    pub const fn with_status(mut self, status: SandboxStatus) -> Self {
        self.status = status;
        self
    }

    /// Validates profile metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.id == INVALID_POLICY_ID {
            return Err(PolicyError::MissingField);
        }
        validate_policy_label(self.label, MAX_SANDBOX_LABEL_LEN)?;
        SandboxResourceSet::from_bits(self.allowed_resources.bits())?;
        CapabilitySet::from_bits(self.capabilities.bits())?;
        self.max_budget.validate()?;
        if self.allowed_resources.is_empty() && !matches!(self.status, SandboxStatus::Disabled) {
            return Err(PolicyError::InvalidResource);
        }
        Ok(())
    }

    /// Evaluates a sandbox request.
    pub fn evaluate(self, request: SandboxRequest<'_>) -> PolicyResult<SandboxDecision> {
        self.validate()?;
        request.validate()?;
        if self.principal_kind as u8 != request.principal.kind as u8 {
            return Ok(SandboxDecision::deny(
                request,
                "principal_kind_mismatch",
                self.audit_on_violation,
            ));
        }
        if matches!(self.status, SandboxStatus::Disabled) {
            return Ok(SandboxDecision::deny(
                request,
                "sandbox_disabled",
                self.audit_on_violation,
            ));
        }
        if self.require_trace && !request.trace.is_present() {
            return Ok(SandboxDecision::deny(
                request,
                PolicyError::InvalidTrace.reason(),
                true,
            ));
        }
        if !self.allowed_resources.contains(request.resource) {
            return self.denied_or_audit_only(request, "resource_denied");
        }
        let required = request.required_capabilities();
        if !request.capabilities.contains_all(required) || !self.capabilities.contains_all(required)
        {
            return self.denied_or_audit_only(request, PolicyError::MissingCapability.reason());
        }
        if !self.max_budget.allows(request.budget) {
            return self.denied_or_audit_only(request, "budget_exceeded");
        }
        if !request.budget.within_deadline(request.monotonic_ns) {
            return self.denied_or_audit_only(request, PolicyError::DeadlineExceeded.reason());
        }
        Ok(SandboxDecision::allow(
            request,
            required,
            request.resource.is_sensitive_boundary(),
        ))
    }

    fn denied_or_audit_only(
        self,
        request: SandboxRequest<'_>,
        reason: &'static str,
    ) -> PolicyResult<SandboxDecision> {
        if matches!(self.status, SandboxStatus::AuditOnly) {
            Ok(SandboxDecision {
                allowed: true,
                reason,
                required_capabilities: request.required_capabilities(),
                audit_required: true,
            })
        } else {
            Ok(SandboxDecision::deny(
                request,
                reason,
                self.audit_on_violation,
            ))
        }
    }
}

/// Sandbox access request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxRequest<'a> {
    /// Principal requesting access.
    pub principal: Principal<'a>,
    /// Resource class.
    pub resource: SandboxResource,
    /// Operation class.
    pub operation: SandboxOperation,
    /// Stable resource label.
    pub resource_label: &'a str,
    /// Capabilities currently held by the principal.
    pub capabilities: CapabilitySet,
    /// Requested budget.
    pub budget: PolicyBudget,
    /// Monotonic timestamp in nanoseconds.
    pub monotonic_ns: u64,
    /// Trace context.
    pub trace: TraceContext,
    /// Data sensitivity.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
}

impl<'a> SandboxRequest<'a> {
    /// Creates a sandbox request.
    pub const fn new(
        principal: Principal<'a>,
        resource: SandboxResource,
        operation: SandboxOperation,
        resource_label: &'a str,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            principal,
            resource,
            operation,
            resource_label,
            capabilities,
            budget: PolicyBudget::UNBOUNDED,
            monotonic_ns: 0,
            trace: TraceContext::EMPTY,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets budget.
    pub const fn with_budget(mut self, budget: PolicyBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Sets monotonic timestamp.
    pub const fn with_time(mut self, monotonic_ns: u64) -> Self {
        self.monotonic_ns = monotonic_ns;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Sets redaction metadata.
    pub const fn with_redaction(
        mut self,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Returns capabilities required for the resource/operation pair.
    pub const fn required_capabilities(self) -> CapabilitySet {
        match (self.resource, self.operation) {
            (SandboxResource::Task, SandboxOperation::Execute | SandboxOperation::Admin) => {
                CapabilitySet::from_known_bits(CAP_TASK_MANAGE)
            }
            (SandboxResource::Memory, SandboxOperation::Read | SandboxOperation::Write) => {
                CapabilitySet::from_known_bits(CAP_MEMORY_MAP)
            }
            (SandboxResource::Memory, SandboxOperation::Open | SandboxOperation::Call) => {
                CapabilitySet::from_known_bits(CAP_MEMORY_SHARE)
            }
            (SandboxResource::Device, SandboxOperation::Open) => {
                CapabilitySet::from_known_bits(CAP_DEVICE_OPEN)
            }
            (SandboxResource::Device, SandboxOperation::Call | SandboxOperation::Write) => {
                CapabilitySet::from_known_bits(CAP_DEVICE_CALL)
            }
            (SandboxResource::Model, SandboxOperation::Infer | SandboxOperation::Call) => {
                CapabilitySet::from_known_bits(CAP_COGNITION_INFER)
            }
            (SandboxResource::Audit, SandboxOperation::Append) => {
                CapabilitySet::from_known_bits(CAP_AUDIT_APPEND)
            }
            (SandboxResource::Audit, SandboxOperation::Read | SandboxOperation::Query) => {
                CapabilitySet::from_known_bits(CAP_AUDIT_QUERY)
            }
            (SandboxResource::Trace, SandboxOperation::Read | SandboxOperation::Append) => {
                CapabilitySet::from_known_bits(CAP_TRACE_CONTEXT)
            }
            (SandboxResource::Policy, SandboxOperation::Read | SandboxOperation::Query) => {
                CapabilitySet::from_known_bits(CAP_POLICY_QUERY)
            }
            (SandboxResource::Config, SandboxOperation::Read | SandboxOperation::Query) => {
                CapabilitySet::from_known_bits(CAP_CONFIG_READ)
            }
            (SandboxResource::Config, _) => CapabilitySet::from_known_bits(CAP_CONFIG_WRITE),
            (SandboxResource::Storage, SandboxOperation::Read | SandboxOperation::Query) => {
                CapabilitySet::from_known_bits(CAP_STORAGE_READ)
            }
            (SandboxResource::Storage, _) => CapabilitySet::from_known_bits(CAP_STORAGE_WRITE),
            _ => CapabilitySet::EMPTY,
        }
    }

    /// Validates request metadata.
    pub fn validate(self) -> PolicyResult<()> {
        self.principal.validate()?;
        validate_policy_label(self.resource_label, MAX_SANDBOX_LABEL_LEN)?;
        CapabilitySet::from_bits(self.capabilities.bits())?;
        self.budget.validate()?;
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Sandbox decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxDecision {
    /// Whether the sandbox permits execution.
    pub allowed: bool,
    /// Stable reason label.
    pub reason: &'static str,
    /// Capabilities required by the request.
    pub required_capabilities: CapabilitySet,
    /// Whether durable audit evidence should be emitted.
    pub audit_required: bool,
}

impl SandboxDecision {
    /// Creates an allow decision.
    pub const fn allow(
        _request: SandboxRequest<'_>,
        required_capabilities: CapabilitySet,
        audit_required: bool,
    ) -> Self {
        Self {
            allowed: true,
            reason: "allow",
            required_capabilities,
            audit_required,
        }
    }

    /// Creates a deny decision.
    pub const fn deny(
        request: SandboxRequest<'_>,
        reason: &'static str,
        audit_required: bool,
    ) -> Self {
        Self {
            allowed: false,
            reason,
            required_capabilities: request.required_capabilities(),
            audit_required,
        }
    }

    /// Returns `true` when execution is permitted.
    pub const fn is_allowed(self) -> bool {
        self.allowed
    }
}

/// Fixed-capacity sandbox profile table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxTable<'a, const N: usize> {
    profiles: [Option<SandboxProfile<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> SandboxTable<'a, N> {
    /// Creates an empty table.
    pub const fn new() -> Self {
        Self {
            profiles: [None; N],
            len: 0,
        }
    }

    /// Returns profile count.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when no profiles are registered.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds a profile.
    pub fn add(&mut self, profile: SandboxProfile<'a>) -> PolicyResult<()> {
        if self.len >= N {
            return Err(PolicyError::CapacityExceeded);
        }
        profile.validate()?;
        if self.find(profile.id).is_some() {
            return Err(PolicyError::Duplicate);
        }
        self.profiles[self.len] = Some(profile);
        self.len += 1;
        Ok(())
    }

    /// Finds a profile by id.
    pub fn find(self, id: u64) -> Option<SandboxProfile<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(profile) = self.profiles[index] {
                if profile.id == id {
                    return Some(profile);
                }
            }
            index += 1;
        }
        None
    }

    /// Finds the first profile matching the principal kind.
    pub fn find_for_principal(self, principal: Principal<'_>) -> Option<SandboxProfile<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(profile) = self.profiles[index] {
                if profile.principal_kind as u8 == principal.kind as u8 {
                    return Some(profile);
                }
            }
            index += 1;
        }
        None
    }
}

impl<'a, const N: usize> Default for SandboxTable<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> SandboxDescriptor<'a> {
    /// Creates a sandbox descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
