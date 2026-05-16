//! Capability taxonomy, principal metadata, and attenuation helpers.
//!
//! Capabilities are represented as stable bit positions. Unknown bits are
//! rejected at trust boundaries and derived grants cannot exceed parent
//! authority or broaden scope.

use crate::{validate_policy_label, PolicyError, PolicyResult};

/// Maximum principal label length accepted by policy APIs.
pub const MAX_PRINCIPAL_LABEL_LEN: usize = 96;

/// Maximum capability namespace or resource scope length.
pub const MAX_CAPABILITY_SCOPE_LEN: usize = 128;

/// Capability grant identifier.
pub type CapabilityId = u64;

/// Invalid capability identifier.
pub const INVALID_CAPABILITY_ID: CapabilityId = 0;

/// Permission to spawn child tasks.
pub const CAP_TASK_SPAWN: u64 = 1 << 0;
/// Permission to manage task lifecycle.
pub const CAP_TASK_MANAGE: u64 = 1 << 1;
/// Permission to map or unmap memory.
pub const CAP_MEMORY_MAP: u64 = 1 << 2;
/// Permission to share or seal memory handles.
pub const CAP_MEMORY_SHARE: u64 = 1 << 3;
/// Permission to list devices.
pub const CAP_DEVICE_LIST: u64 = 1 << 4;
/// Permission to open devices.
pub const CAP_DEVICE_OPEN: u64 = 1 << 5;
/// Permission to call devices.
pub const CAP_DEVICE_CALL: u64 = 1 << 6;
/// Permission to invoke cognition inference.
pub const CAP_COGNITION_INFER: u64 = 1 << 7;
/// Permission to write cognition memory.
pub const CAP_COGNITION_MEMORY_WRITE: u64 = 1 << 8;
/// Permission to derive, revoke, or administer capabilities.
pub const CAP_CAPABILITY_ADMIN: u64 = 1 << 9;
/// Permission to request attestation material.
pub const CAP_ATTEST: u64 = 1 << 10;
/// Permission to request random bytes.
pub const CAP_RANDOM: u64 = 1 << 11;
/// Permission to append audit records.
pub const CAP_AUDIT_APPEND: u64 = 1 << 12;
/// Permission to query audit records.
pub const CAP_AUDIT_QUERY: u64 = 1 << 13;
/// Permission to verify audit evidence.
pub const CAP_AUDIT_VERIFY: u64 = 1 << 14;
/// Permission to emit or carry trace context.
pub const CAP_TRACE_CONTEXT: u64 = 1 << 15;
/// Permission to query policy decisions.
pub const CAP_POLICY_QUERY: u64 = 1 << 16;
/// Permission to load, replace, or seal policy bundles.
pub const CAP_POLICY_MANAGE: u64 = 1 << 17;
/// Permission to read configuration records.
pub const CAP_CONFIG_READ: u64 = 1 << 18;
/// Permission to mutate configuration records.
pub const CAP_CONFIG_WRITE: u64 = 1 << 19;
/// Permission to read persistent storage.
pub const CAP_STORAGE_READ: u64 = 1 << 20;
/// Permission to mutate persistent storage.
pub const CAP_STORAGE_WRITE: u64 = 1 << 21;

/// All capability bits known by this crate version.
pub const KNOWN_CAPABILITY_BITS: u64 = CAP_TASK_SPAWN
    | CAP_TASK_MANAGE
    | CAP_MEMORY_MAP
    | CAP_MEMORY_SHARE
    | CAP_DEVICE_LIST
    | CAP_DEVICE_OPEN
    | CAP_DEVICE_CALL
    | CAP_COGNITION_INFER
    | CAP_COGNITION_MEMORY_WRITE
    | CAP_CAPABILITY_ADMIN
    | CAP_ATTEST
    | CAP_RANDOM
    | CAP_AUDIT_APPEND
    | CAP_AUDIT_QUERY
    | CAP_AUDIT_VERIFY
    | CAP_TRACE_CONTEXT
    | CAP_POLICY_QUERY
    | CAP_POLICY_MANAGE
    | CAP_CONFIG_READ
    | CAP_CONFIG_WRITE
    | CAP_STORAGE_READ
    | CAP_STORAGE_WRITE;

/// Stable capability taxonomy used by policy rules.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Spawn a new task.
    TaskSpawn = 0,
    /// Manage an existing task.
    TaskManage = 1,
    /// Map or unmap memory.
    MemoryMap = 2,
    /// Share or seal memory.
    MemoryShare = 3,
    /// Enumerate devices.
    DeviceList = 4,
    /// Open a device.
    DeviceOpen = 5,
    /// Call an opened device.
    DeviceCall = 6,
    /// Invoke model or accelerator inference.
    CognitionInfer = 7,
    /// Mutate cognitive memory.
    CognitionMemoryWrite = 8,
    /// Administer capabilities.
    CapabilityAdmin = 9,
    /// Request attestation material.
    Attest = 10,
    /// Request random bytes.
    Random = 11,
    /// Append audit records.
    AuditAppend = 12,
    /// Query audit records.
    AuditQuery = 13,
    /// Verify audit records.
    AuditVerify = 14,
    /// Propagate trace context.
    TraceContext = 15,
    /// Query policy decisions.
    PolicyQuery = 16,
    /// Manage policy bundles.
    PolicyManage = 17,
    /// Read configuration.
    ConfigRead = 18,
    /// Mutate configuration.
    ConfigWrite = 19,
    /// Read persistent storage.
    StorageRead = 20,
    /// Mutate persistent storage.
    StorageWrite = 21,
}

impl Capability {
    /// Returns the bit mask for this capability.
    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    /// Stable label for manifests, diagnostics, and audit records.
    pub const fn label(self) -> &'static str {
        match self {
            Self::TaskSpawn => "task.spawn",
            Self::TaskManage => "task.manage",
            Self::MemoryMap => "memory.map",
            Self::MemoryShare => "memory.share",
            Self::DeviceList => "device.list",
            Self::DeviceOpen => "device.open",
            Self::DeviceCall => "device.call",
            Self::CognitionInfer => "cognition.infer",
            Self::CognitionMemoryWrite => "cognition.memory.write",
            Self::CapabilityAdmin => "capability.admin",
            Self::Attest => "attest",
            Self::Random => "random",
            Self::AuditAppend => "audit.append",
            Self::AuditQuery => "audit.query",
            Self::AuditVerify => "audit.verify",
            Self::TraceContext => "trace.context",
            Self::PolicyQuery => "policy.query",
            Self::PolicyManage => "policy.manage",
            Self::ConfigRead => "config.read",
            Self::ConfigWrite => "config.write",
            Self::StorageRead => "storage.read",
            Self::StorageWrite => "storage.write",
        }
    }

    /// Converts a stable label into a capability.
    pub const fn from_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"task.spawn" => Some(Self::TaskSpawn),
            b"task.manage" => Some(Self::TaskManage),
            b"memory.map" => Some(Self::MemoryMap),
            b"memory.share" => Some(Self::MemoryShare),
            b"device.list" => Some(Self::DeviceList),
            b"device.open" => Some(Self::DeviceOpen),
            b"device.call" => Some(Self::DeviceCall),
            b"cognition.infer" => Some(Self::CognitionInfer),
            b"cognition.memory.write" => Some(Self::CognitionMemoryWrite),
            b"capability.admin" => Some(Self::CapabilityAdmin),
            b"attest" => Some(Self::Attest),
            b"random" => Some(Self::Random),
            b"audit.append" => Some(Self::AuditAppend),
            b"audit.query" => Some(Self::AuditQuery),
            b"audit.verify" => Some(Self::AuditVerify),
            b"trace.context" => Some(Self::TraceContext),
            b"policy.query" => Some(Self::PolicyQuery),
            b"policy.manage" => Some(Self::PolicyManage),
            b"config.read" => Some(Self::ConfigRead),
            b"config.write" => Some(Self::ConfigWrite),
            b"storage.read" => Some(Self::StorageRead),
            b"storage.write" => Some(Self::StorageWrite),
            _ => None,
        }
    }
}

/// Compact set of policy capability bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    /// Empty set used by deny-by-default callers.
    pub const EMPTY: Self = Self { bits: 0 };

    /// All capabilities known by this crate version.
    pub const ALL: Self = Self {
        bits: KNOWN_CAPABILITY_BITS,
    };

    /// Creates a set containing a single capability.
    pub const fn single(capability: Capability) -> Self {
        Self {
            bits: capability.bit(),
        }
    }

    /// Creates a set from raw bits, rejecting unknown bits.
    pub const fn from_bits(bits: u64) -> PolicyResult<Self> {
        if bits & !KNOWN_CAPABILITY_BITS != 0 {
            Err(PolicyError::ReservedBits)
        } else {
            Ok(Self { bits })
        }
    }

    /// Creates a set from known bits without validation.
    pub const fn from_known_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns the raw capability mask.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns `true` when no authority is present.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns `true` when this set includes the capability.
    pub const fn contains(self, capability: Capability) -> bool {
        self.bits & capability.bit() != 0
    }

    /// Returns `true` when all capabilities in `required` are present.
    pub const fn contains_all(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }

    /// Returns a set with an additional known capability.
    pub const fn with(self, capability: Capability) -> Self {
        Self {
            bits: self.bits | capability.bit(),
        }
    }

    /// Returns the union of two capability sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns the intersection of two capability sets.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Returns `requested` if it is attenuated from this set.
    pub const fn derive(self, requested: Self) -> PolicyResult<Self> {
        if self.contains_all(requested) {
            Ok(requested)
        } else {
            Err(PolicyError::MissingCapability)
        }
    }

    /// Fails when required capabilities are absent.
    pub const fn require(self, required: Self) -> PolicyResult<()> {
        if self.contains_all(required) {
            Ok(())
        } else {
            Err(PolicyError::MissingCapability)
        }
    }

    /// Converts a stable capability label into a singleton set.
    pub const fn named(label: &str) -> Option<Self> {
        match Capability::from_label(label) {
            Some(capability) => Some(Self::single(capability)),
            None => None,
        }
    }
}

/// Principal classes named in the security model.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    /// Kernel authority.
    Kernel = 1,
    /// Runtime service authority.
    Runtime = 2,
    /// Agent workload authority.
    Agent = 3,
    /// Human or automated operator.
    Operator = 4,
    /// Device or driver authority.
    Device = 5,
    /// Long-running service authority.
    Service = 6,
    /// Corpus contributor identity.
    CorpusContributor = 7,
    /// Anonymous or unauthenticated principal.
    Anonymous = 8,
}

impl PrincipalKind {
    /// Parses a stable principal-kind label.
    pub const fn from_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"kernel" => Some(Self::Kernel),
            b"runtime" => Some(Self::Runtime),
            b"agent" => Some(Self::Agent),
            b"operator" => Some(Self::Operator),
            b"device" => Some(Self::Device),
            b"service" => Some(Self::Service),
            b"corpus_contributor" => Some(Self::CorpusContributor),
            b"anonymous" => Some(Self::Anonymous),
            _ => None,
        }
    }

    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Runtime => "runtime",
            Self::Agent => "agent",
            Self::Operator => "operator",
            Self::Device => "device",
            Self::Service => "service",
            Self::CorpusContributor => "corpus_contributor",
            Self::Anonymous => "anonymous",
        }
    }

    /// Returns `true` when this principal kind can hold administrative rights.
    pub const fn can_administer(self) -> bool {
        matches!(self, Self::Kernel | Self::Runtime | Self::Operator)
    }
}

/// Borrowed principal identity metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Principal<'a> {
    /// Principal kind.
    pub kind: PrincipalKind,
    /// Stable principal label.
    pub id: &'a str,
    /// Optional session label.
    pub session: &'a str,
}

impl<'a> Principal<'a> {
    /// Creates a principal without session metadata.
    pub const fn new(kind: PrincipalKind, id: &'a str) -> Self {
        Self {
            kind,
            id,
            session: "",
        }
    }

    /// Attaches a session label.
    pub const fn with_session(mut self, session: &'a str) -> Self {
        self.session = session;
        self
    }

    /// Validates principal labels.
    pub fn validate(self) -> PolicyResult<()> {
        validate_policy_label(self.id, MAX_PRINCIPAL_LABEL_LEN)?;
        if !self.session.is_empty() && self.session.len() > MAX_PRINCIPAL_LABEL_LEN {
            return Err(PolicyError::FieldTooLong);
        }
        Ok(())
    }
}

/// Resource scope attached to a capability grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityScope<'a> {
    /// Namespace, subsystem, or resource class. `"*"` means any namespace.
    pub namespace: &'a str,
    /// Resource label. `"*"` means any resource within the namespace.
    pub resource: &'a str,
}

impl<'a> CapabilityScope<'a> {
    /// Scope covering all namespaces and resources.
    pub const ANY: Self = Self {
        namespace: "*",
        resource: "*",
    };

    /// Creates a scope.
    pub const fn new(namespace: &'a str, resource: &'a str) -> Self {
        Self {
            namespace,
            resource,
        }
    }

    /// Returns `true` when the scope can apply to any resource.
    pub fn is_any(self) -> bool {
        self.namespace.as_bytes() == b"*" && self.resource.as_bytes() == b"*"
    }

    /// Validates scope labels.
    pub fn validate(self) -> PolicyResult<()> {
        validate_policy_label(self.namespace, MAX_CAPABILITY_SCOPE_LEN)?;
        validate_policy_label(self.resource, MAX_CAPABILITY_SCOPE_LEN)
    }

    /// Returns `true` when this scope allows the supplied namespace/resource.
    pub fn allows(self, namespace: &str, resource: &str) -> bool {
        (self.namespace.as_bytes() == b"*" || self.namespace.as_bytes() == namespace.as_bytes())
            && (self.resource.as_bytes() == b"*" || self.resource.as_bytes() == resource.as_bytes())
    }

    /// Returns `true` when `child` is no broader than this scope.
    pub fn contains(self, child: Self) -> bool {
        (self.namespace.as_bytes() == b"*"
            || self.namespace.as_bytes() == child.namespace.as_bytes())
            && (self.resource.as_bytes() == b"*"
                || self.resource.as_bytes() == child.resource.as_bytes())
    }
}

/// Capability grant metadata before enforcement by a runtime or kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityGrant<'a> {
    /// Stable grant identifier. Zero is invalid.
    pub id: CapabilityId,
    /// Issuer principal.
    pub issuer: Principal<'a>,
    /// Subject principal.
    pub subject: Principal<'a>,
    /// Attenuated rights.
    pub rights: CapabilitySet,
    /// Resource scope.
    pub scope: CapabilityScope<'a>,
    /// Absolute expiration time in nanoseconds. Zero means no expiration.
    pub expires_at_ns: u64,
    /// Generation used to reject stale handles.
    pub generation: u32,
    /// Number of derivations from root authority.
    pub attenuation_depth: u8,
    /// Whether the grant has been revoked.
    pub revoked: bool,
}

impl<'a> CapabilityGrant<'a> {
    /// Creates a capability grant.
    pub const fn new(
        id: CapabilityId,
        issuer: Principal<'a>,
        subject: Principal<'a>,
        rights: CapabilitySet,
        scope: CapabilityScope<'a>,
        generation: u32,
    ) -> Self {
        Self {
            id,
            issuer,
            subject,
            rights,
            scope,
            expires_at_ns: 0,
            generation,
            attenuation_depth: 0,
            revoked: false,
        }
    }

    /// Sets grant expiration.
    pub const fn with_expiration(mut self, expires_at_ns: u64) -> Self {
        self.expires_at_ns = expires_at_ns;
        self
    }

    /// Marks the grant as revoked.
    pub const fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Validates principal, rights, scope, and generation metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.id == INVALID_CAPABILITY_ID || self.generation == 0 || self.rights.is_empty() {
            return Err(PolicyError::InvalidCapability);
        }
        self.issuer.validate()?;
        self.subject.validate()?;
        self.scope.validate()?;
        CapabilitySet::from_bits(self.rights.bits())?;
        if self.revoked {
            return Err(PolicyError::InvalidCapability);
        }
        Ok(())
    }

    /// Returns `true` when this grant can be used at the supplied time.
    pub const fn is_active(self, now_ns: u64) -> bool {
        !self.revoked && (self.expires_at_ns == 0 || now_ns <= self.expires_at_ns)
    }

    /// Checks authority, scope, and lifetime for this grant.
    pub fn authorize(
        self,
        required: CapabilitySet,
        namespace: &str,
        resource: &str,
        now_ns: u64,
    ) -> PolicyResult<()> {
        self.validate()?;
        if !self.is_active(now_ns) {
            return Err(PolicyError::MissingCapability);
        }
        if !self.scope.allows(namespace, resource) {
            return Err(PolicyError::MissingCapability);
        }
        self.rights.require(required)
    }

    /// Derives an attenuated child grant.
    pub fn derive(
        self,
        child_id: CapabilityId,
        child_subject: Principal<'a>,
        requested_rights: CapabilitySet,
        child_scope: CapabilityScope<'a>,
        child_generation: u32,
    ) -> PolicyResult<Self> {
        self.validate()?;
        if !self.issuer.kind.can_administer() && !self.rights.contains(Capability::CapabilityAdmin)
        {
            return Err(PolicyError::MissingCapability);
        }
        self.rights.derive(requested_rights)?;
        if !self.scope.contains(child_scope) {
            return Err(PolicyError::MissingCapability);
        }
        child_subject.validate()?;
        child_scope.validate()?;
        Ok(Self {
            id: child_id,
            issuer: self.subject,
            subject: child_subject,
            rights: requested_rights,
            scope: child_scope,
            expires_at_ns: self.expires_at_ns,
            generation: child_generation,
            attenuation_depth: self.attenuation_depth.saturating_add(1),
            revoked: false,
        })
    }

    /// Returns `true` when changes to this grant require audit evidence.
    pub const fn requires_audit(self) -> bool {
        !self.rights.is_empty()
    }
}

/// Fixed-capacity capability grant table for host-mode tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityTable<'a, const N: usize> {
    grants: [Option<CapabilityGrant<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> CapabilityTable<'a, N> {
    /// Creates an empty table.
    pub const fn new() -> Self {
        Self {
            grants: [None; N],
            len: 0,
        }
    }

    /// Returns the number of active table entries.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when the table is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds a validated grant.
    pub fn add(&mut self, grant: CapabilityGrant<'a>) -> PolicyResult<()> {
        if self.len >= N {
            return Err(PolicyError::CapacityExceeded);
        }
        grant.validate()?;
        if self.find(grant.id).is_some() {
            return Err(PolicyError::Duplicate);
        }
        self.grants[self.len] = Some(grant);
        self.len += 1;
        Ok(())
    }

    /// Finds a grant by id.
    pub fn find(self, id: CapabilityId) -> Option<CapabilityGrant<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(grant) = self.grants[index] {
                if grant.id == id {
                    return Some(grant);
                }
            }
            index += 1;
        }
        None
    }

    /// Revokes a grant by id.
    pub fn revoke(&mut self, id: CapabilityId) -> PolicyResult<CapabilityGrant<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(mut grant) = self.grants[index] {
                if grant.id == id {
                    grant.revoked = true;
                    self.grants[index] = Some(grant);
                    return Ok(grant);
                }
            }
            index += 1;
        }
        Err(PolicyError::NotFound)
    }

    /// Authorizes through a table grant.
    pub fn authorize(
        self,
        id: CapabilityId,
        required: CapabilitySet,
        namespace: &str,
        resource: &str,
        now_ns: u64,
    ) -> PolicyResult<()> {
        let Some(grant) = self.find(id) else {
            return Err(PolicyError::NotFound);
        };
        grant.authorize(required, namespace, resource, now_ns)
    }
}

impl<'a, const N: usize> Default for CapabilityTable<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> CapabilityDescriptor<'a> {
    /// Creates a capability descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
