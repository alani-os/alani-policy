//! Declarative policy rules and fixed-capacity rule sets.
//!
//! Rules are intentionally simple and inspectable: they match a principal,
//! operation, resource kind, and resource label, then produce an effect. The
//! evaluator applies deny-by-default semantics when no rule matches.

use crate::capability::{
    Capability, CapabilitySet, Principal, PrincipalKind, CAP_AUDIT_APPEND, CAP_AUDIT_QUERY,
    CAP_AUDIT_VERIFY, CAP_CAPABILITY_ADMIN, CAP_COGNITION_INFER, CAP_COGNITION_MEMORY_WRITE,
    CAP_CONFIG_READ, CAP_CONFIG_WRITE, CAP_DEVICE_CALL, CAP_DEVICE_LIST, CAP_DEVICE_OPEN,
    CAP_MEMORY_MAP, CAP_MEMORY_SHARE, CAP_POLICY_MANAGE, CAP_POLICY_QUERY, CAP_STORAGE_READ,
    CAP_STORAGE_WRITE, CAP_TASK_MANAGE, CAP_TASK_SPAWN, CAP_TRACE_CONTEXT,
};
use crate::{validate_policy_label, PolicyBudget, PolicyError, PolicyResult, INVALID_POLICY_ID};

/// Maximum policy rule label length.
pub const MAX_RULE_LABEL_LEN: usize = 128;

/// Resource kind used by policy and sandbox checks.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// Matches any resource kind.
    Any = 0,
    /// Task or process resource.
    Task = 1,
    /// Memory mapping or shared-memory resource.
    Memory = 2,
    /// Device resource.
    Device = 3,
    /// Model or cognitive accelerator resource.
    Model = 4,
    /// Audit stream, query, or proof resource.
    AuditLog = 5,
    /// Trace or observability resource.
    Trace = 6,
    /// Policy bundle or evaluator resource.
    Policy = 7,
    /// Configuration resource.
    Config = 8,
    /// Persistent storage resource.
    Storage = 9,
    /// Filesystem resource.
    Filesystem = 10,
    /// Network resource.
    Network = 11,
    /// Corpus record or split resource.
    Corpus = 12,
    /// Package or release artifact resource.
    Package = 13,
    /// Identity, credential, or session resource.
    Identity = 14,
}

impl ResourceKind {
    /// Stable resource label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Task => "task",
            Self::Memory => "memory",
            Self::Device => "device",
            Self::Model => "model",
            Self::AuditLog => "audit_log",
            Self::Trace => "trace",
            Self::Policy => "policy",
            Self::Config => "config",
            Self::Storage => "storage",
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Corpus => "corpus",
            Self::Package => "package",
            Self::Identity => "identity",
        }
    }

    /// Returns `true` when operations on this resource should be audited.
    pub const fn is_audit_critical(self) -> bool {
        matches!(
            self,
            Self::Device
                | Self::Memory
                | Self::Model
                | Self::AuditLog
                | Self::Policy
                | Self::Config
                | Self::Storage
                | Self::Identity
                | Self::Package
        )
    }
}

/// Operation kind used by policy and sandbox checks.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Matches any operation.
    Any = 0,
    /// Read or inspect.
    Read = 1,
    /// Write or mutate.
    Write = 2,
    /// Create a resource.
    Create = 3,
    /// Delete a resource.
    Delete = 4,
    /// Execute a task or action.
    Execute = 5,
    /// Administrative operation.
    Admin = 6,
    /// Query metadata or records.
    Query = 7,
    /// Open a handle.
    Open = 8,
    /// Call an opened resource.
    Call = 9,
    /// Invoke cognition inference.
    Infer = 10,
    /// Append audit or journal evidence.
    Append = 11,
    /// Verify evidence.
    Verify = 12,
    /// Derive a capability.
    DeriveCapability = 13,
    /// Revoke a capability.
    RevokeCapability = 14,
    /// Export data.
    Export = 15,
    /// Route or forward a message.
    Route = 16,
    /// Mount or bind storage/filesystem resources.
    Mount = 17,
}

impl OperationKind {
    /// Stable operation label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Read => "read",
            Self::Write => "write",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Execute => "execute",
            Self::Admin => "admin",
            Self::Query => "query",
            Self::Open => "open",
            Self::Call => "call",
            Self::Infer => "infer",
            Self::Append => "append",
            Self::Verify => "verify",
            Self::DeriveCapability => "capability.derive",
            Self::RevokeCapability => "capability.revoke",
            Self::Export => "export",
            Self::Route => "route",
            Self::Mount => "mount",
        }
    }

    /// Returns `true` when this operation changes authority or persistent state.
    pub const fn is_audit_critical(self) -> bool {
        matches!(
            self,
            Self::Write
                | Self::Create
                | Self::Delete
                | Self::Execute
                | Self::Admin
                | Self::Open
                | Self::Call
                | Self::Infer
                | Self::Append
                | Self::Verify
                | Self::DeriveCapability
                | Self::RevokeCapability
                | Self::Export
                | Self::Route
                | Self::Mount
        )
    }

    /// Baseline capability required for a resource/operation pair.
    pub const fn required_capabilities(self, resource: ResourceKind) -> CapabilitySet {
        match (resource, self) {
            (ResourceKind::Task, OperationKind::Create) => {
                CapabilitySet::from_known_bits(CAP_TASK_SPAWN)
            }
            (ResourceKind::Task, OperationKind::Admin | OperationKind::Delete) => {
                CapabilitySet::from_known_bits(CAP_TASK_MANAGE)
            }
            (ResourceKind::Memory, OperationKind::Read | OperationKind::Write) => {
                CapabilitySet::from_known_bits(CAP_MEMORY_MAP)
            }
            (ResourceKind::Memory, OperationKind::Create | OperationKind::Export) => {
                CapabilitySet::from_known_bits(CAP_MEMORY_SHARE)
            }
            (ResourceKind::Device, OperationKind::Query | OperationKind::Read) => {
                CapabilitySet::from_known_bits(CAP_DEVICE_LIST)
            }
            (ResourceKind::Device, OperationKind::Open) => {
                CapabilitySet::from_known_bits(CAP_DEVICE_OPEN)
            }
            (ResourceKind::Device, OperationKind::Call | OperationKind::Write) => {
                CapabilitySet::from_known_bits(CAP_DEVICE_CALL)
            }
            (ResourceKind::Model, OperationKind::Infer | OperationKind::Call) => {
                CapabilitySet::from_known_bits(CAP_COGNITION_INFER)
            }
            (ResourceKind::Model, OperationKind::Write) => {
                CapabilitySet::from_known_bits(CAP_COGNITION_MEMORY_WRITE)
            }
            (ResourceKind::AuditLog, OperationKind::Append) => {
                CapabilitySet::from_known_bits(CAP_AUDIT_APPEND)
            }
            (ResourceKind::AuditLog, OperationKind::Query | OperationKind::Read) => {
                CapabilitySet::from_known_bits(CAP_AUDIT_QUERY)
            }
            (ResourceKind::AuditLog, OperationKind::Verify) => {
                CapabilitySet::from_known_bits(CAP_AUDIT_VERIFY)
            }
            (
                ResourceKind::Trace,
                OperationKind::Read | OperationKind::Append | OperationKind::Export,
            ) => CapabilitySet::from_known_bits(CAP_TRACE_CONTEXT),
            (ResourceKind::Policy, OperationKind::Query | OperationKind::Read) => {
                CapabilitySet::from_known_bits(CAP_POLICY_QUERY)
            }
            (ResourceKind::Policy, OperationKind::Admin | OperationKind::Write) => {
                CapabilitySet::from_known_bits(CAP_POLICY_MANAGE)
            }
            (ResourceKind::Config, OperationKind::Read | OperationKind::Query) => {
                CapabilitySet::from_known_bits(CAP_CONFIG_READ)
            }
            (ResourceKind::Config, OperationKind::Write | OperationKind::Admin) => {
                CapabilitySet::from_known_bits(CAP_CONFIG_WRITE)
            }
            (
                ResourceKind::Storage | ResourceKind::Filesystem,
                OperationKind::Read | OperationKind::Query,
            ) => CapabilitySet::from_known_bits(CAP_STORAGE_READ),
            (ResourceKind::Storage | ResourceKind::Filesystem, _) => {
                CapabilitySet::from_known_bits(CAP_STORAGE_WRITE)
            }
            (_, OperationKind::DeriveCapability | OperationKind::RevokeCapability) => {
                CapabilitySet::from_known_bits(CAP_CAPABILITY_ADMIN)
            }
            (_, OperationKind::Admin) => {
                CapabilitySet::from_known_bits(Capability::CapabilityAdmin.bit())
            }
            _ => CapabilitySet::EMPTY,
        }
    }
}

/// Effect produced by a matching policy rule.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyEffect {
    /// Request may execute.
    Allow = 1,
    /// Request is denied.
    Deny = 2,
    /// Request requires operator or higher-layer escalation.
    RequireEscalation = 3,
    /// Request may proceed only when audit evidence is emitted.
    RequireAudit = 4,
}

impl PolicyEffect {
    /// Stable effect label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireEscalation => "require_escalation",
            Self::RequireAudit => "require_audit",
        }
    }

    /// Returns `true` when the effect permits execution.
    pub const fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::RequireAudit)
    }
}

/// Declarative policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRule<'a> {
    /// Stable rule identifier. Zero is invalid.
    pub id: u64,
    /// Stable rule label.
    pub label: &'a str,
    /// Rule effect.
    pub effect: PolicyEffect,
    /// Optional principal kind filter.
    pub principal_kind: Option<PrincipalKind>,
    /// Optional principal id filter. Empty string means any principal id.
    pub principal_id: &'a str,
    /// Resource kind filter.
    pub resource_kind: ResourceKind,
    /// Resource label filter. `"*"` means any resource label.
    pub resource: &'a str,
    /// Operation filter.
    pub operation: OperationKind,
    /// Additional required capabilities.
    pub required_capabilities: CapabilitySet,
    /// Maximum budget this rule permits. Unbounded means no rule-level maximum.
    pub max_budget: PolicyBudget,
    /// Rule priority. Higher values win; deny wins equal priority.
    pub priority: u16,
    /// Whether matching decisions must emit audit evidence.
    pub audit_required: bool,
    /// Whether the rule is active.
    pub enabled: bool,
}

impl<'a> PolicyRule<'a> {
    /// Creates a rule with conservative defaults.
    pub const fn new(
        id: u64,
        label: &'a str,
        effect: PolicyEffect,
        resource_kind: ResourceKind,
        operation: OperationKind,
    ) -> Self {
        Self {
            id,
            label,
            effect,
            principal_kind: None,
            principal_id: "",
            resource_kind,
            resource: "*",
            operation,
            required_capabilities: CapabilitySet::EMPTY,
            max_budget: PolicyBudget::UNBOUNDED,
            priority: 0,
            audit_required: true,
            enabled: true,
        }
    }

    /// Sets a principal-kind filter.
    pub const fn for_principal_kind(mut self, kind: PrincipalKind) -> Self {
        self.principal_kind = Some(kind);
        self
    }

    /// Sets a principal-id filter.
    pub const fn for_principal_id(mut self, principal_id: &'a str) -> Self {
        self.principal_id = principal_id;
        self
    }

    /// Sets a resource-label filter.
    pub const fn for_resource(mut self, resource: &'a str) -> Self {
        self.resource = resource;
        self
    }

    /// Adds required capabilities.
    pub const fn with_required_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.required_capabilities = capabilities;
        self
    }

    /// Sets a rule-level maximum budget.
    pub const fn with_max_budget(mut self, budget: PolicyBudget) -> Self {
        self.max_budget = budget;
        self
    }

    /// Sets priority.
    pub const fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Sets audit requirement.
    pub const fn with_audit_required(mut self, audit_required: bool) -> Self {
        self.audit_required = audit_required;
        self
    }

    /// Disables the rule.
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Validates rule metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.id == INVALID_POLICY_ID {
            return Err(PolicyError::InvalidRule);
        }
        validate_policy_label(self.label, MAX_RULE_LABEL_LEN)?;
        if !self.principal_id.is_empty() {
            validate_policy_label(self.principal_id, MAX_RULE_LABEL_LEN)?;
        }
        validate_policy_label(self.resource, MAX_RULE_LABEL_LEN)?;
        CapabilitySet::from_bits(self.required_capabilities.bits())?;
        self.max_budget.validate()?;
        if !self.enabled {
            return Err(PolicyError::InvalidRule);
        }
        Ok(())
    }

    /// Returns `true` when this rule matches the request tuple.
    pub fn matches(
        self,
        principal: Principal<'_>,
        resource_kind: ResourceKind,
        resource: &str,
        operation: OperationKind,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(kind) = self.principal_kind {
            if kind as u8 != principal.kind as u8 {
                return false;
            }
        }
        if !self.principal_id.is_empty() && self.principal_id.as_bytes() != principal.id.as_bytes()
        {
            return false;
        }
        if !matches!(self.resource_kind, ResourceKind::Any)
            && self.resource_kind as u8 != resource_kind as u8
        {
            return false;
        }
        if self.resource.as_bytes() != b"*" && self.resource.as_bytes() != resource.as_bytes() {
            return false;
        }
        if !matches!(self.operation, OperationKind::Any) && self.operation as u8 != operation as u8
        {
            return false;
        }
        true
    }
}

/// Fixed-capacity policy rule set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRuleSet<'a, const N: usize> {
    rules: [Option<PolicyRule<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> PolicyRuleSet<'a, N> {
    /// Creates an empty rule set.
    pub const fn new() -> Self {
        Self {
            rules: [None; N],
            len: 0,
        }
    }

    /// Returns the number of rules.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when the set has no rules.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds a rule.
    pub fn add_rule(&mut self, rule: PolicyRule<'a>) -> PolicyResult<()> {
        if self.len >= N {
            return Err(PolicyError::CapacityExceeded);
        }
        rule.validate()?;
        if self.find(rule.id).is_some() {
            return Err(PolicyError::Duplicate);
        }
        self.rules[self.len] = Some(rule);
        self.len += 1;
        Ok(())
    }

    /// Finds a rule by id.
    pub fn find(self, id: u64) -> Option<PolicyRule<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(rule) = self.rules[index] {
                if rule.id == id {
                    return Some(rule);
                }
            }
            index += 1;
        }
        None
    }

    /// Finds the best matching rule for a request tuple.
    pub fn select(
        self,
        principal: Principal<'_>,
        resource_kind: ResourceKind,
        resource: &str,
        operation: OperationKind,
    ) -> PolicyResult<Option<PolicyRule<'a>>> {
        principal.validate()?;
        validate_policy_label(resource, MAX_RULE_LABEL_LEN)?;
        let mut selected: Option<PolicyRule<'a>> = None;
        let mut index = 0;
        while index < self.len {
            let Some(rule) = self.rules[index] else {
                return Err(PolicyError::Internal);
            };
            if rule.matches(principal, resource_kind, resource, operation) {
                rule.validate()?;
                selected = match selected {
                    None => Some(rule),
                    Some(current) => {
                        if rule.priority > current.priority
                            || (rule.priority == current.priority
                                && matches!(rule.effect, PolicyEffect::Deny)
                                && !matches!(current.effect, PolicyEffect::Deny))
                        {
                            Some(rule)
                        } else {
                            Some(current)
                        }
                    }
                };
            }
            index += 1;
        }
        Ok(selected)
    }
}

impl<'a, const N: usize> Default for PolicyRuleSet<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RulesDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> RulesDescriptor<'a> {
    /// Creates a rules descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
