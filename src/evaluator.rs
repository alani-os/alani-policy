//! Policy evaluator contracts and audit-facing decision records.
//!
//! The evaluator applies validation, capability checks, budget checks, rule
//! matching, and deny-by-default behavior. It does not execute privileged
//! operations; it returns structured decisions for enforcement layers.

use crate::capability::{CapabilitySet, Principal};
use crate::rules::{OperationKind, PolicyEffect, PolicyRule, PolicyRuleSet, ResourceKind};
use crate::{
    validate_policy_label, validate_redaction, DataClass, PolicyBudget, PolicyError, PolicyResult,
    RedactionState, TraceContext, INVALID_POLICY_ID, MAX_POLICY_LABEL_LEN,
};

/// Policy decision vocabulary aligned with the ABI draft.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    /// Request may execute.
    Allow = 1,
    /// Request is denied.
    Deny = 2,
    /// Request requires operator or higher-layer escalation.
    RequireEscalation = 3,
    /// Request may proceed only when audit evidence is emitted.
    RequireAudit = 4,
}

impl PolicyDecision {
    /// Parses a stable decision label.
    pub const fn from_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"allow" => Some(Self::Allow),
            b"deny" => Some(Self::Deny),
            b"require_escalation" => Some(Self::RequireEscalation),
            b"require_audit" => Some(Self::RequireAudit),
            _ => None,
        }
    }

    /// Stable decision label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireEscalation => "require_escalation",
            Self::RequireAudit => "require_audit",
        }
    }

    /// Returns `true` when the decision permits execution.
    pub const fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::RequireAudit)
    }

    /// Converts a rule effect to an evaluator decision.
    pub const fn from_effect(effect: PolicyEffect) -> Self {
        match effect {
            PolicyEffect::Allow => Self::Allow,
            PolicyEffect::Deny => Self::Deny,
            PolicyEffect::RequireEscalation => Self::RequireEscalation,
            PolicyEffect::RequireAudit => Self::RequireAudit,
        }
    }
}

/// Context metadata supplied to policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationContext {
    /// Monotonic timestamp in nanoseconds when available.
    pub monotonic_ns: u64,
    /// Trace context propagated from the caller.
    pub trace: TraceContext,
    /// Sensitivity of diagnostic metadata.
    pub data_class: DataClass,
    /// Redaction state of diagnostic metadata.
    pub redaction: RedactionState,
    /// Caller already requires durable audit evidence.
    pub audit_required: bool,
}

impl EvaluationContext {
    /// Conservative empty context.
    pub const EMPTY: Self = Self {
        monotonic_ns: 0,
        trace: TraceContext::EMPTY,
        data_class: DataClass::Operational,
        redaction: RedactionState::Operational,
        audit_required: false,
    };

    /// Creates an evaluation context.
    pub const fn new(monotonic_ns: u64, trace: TraceContext) -> Self {
        Self {
            monotonic_ns,
            trace,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            audit_required: false,
        }
    }

    /// Sets data classification.
    pub const fn with_redaction(
        mut self,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Requires durable audit evidence.
    pub const fn with_audit_required(mut self, audit_required: bool) -> Self {
        self.audit_required = audit_required;
        self
    }

    /// Validates trace and redaction metadata.
    pub fn validate(self) -> PolicyResult<()> {
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Policy request evaluated by a policy engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRequest<'a> {
    /// Stable request identifier. Zero is invalid for auditable requests.
    pub request_id: u64,
    /// Principal requesting authority.
    pub principal: Principal<'a>,
    /// Operation being requested.
    pub operation: OperationKind,
    /// Resource kind.
    pub resource_kind: ResourceKind,
    /// Resource label.
    pub resource: &'a str,
    /// Explicit capabilities requested by the caller.
    pub requested_capabilities: CapabilitySet,
    /// Capabilities offered by the caller.
    pub offered_capabilities: CapabilitySet,
    /// Requested resource budget.
    pub budget: PolicyBudget,
    /// Evaluation context.
    pub context: EvaluationContext,
}

impl<'a> PolicyRequest<'a> {
    /// Creates a policy request.
    pub const fn new(
        request_id: u64,
        principal: Principal<'a>,
        operation: OperationKind,
        resource_kind: ResourceKind,
        resource: &'a str,
        offered_capabilities: CapabilitySet,
    ) -> Self {
        Self {
            request_id,
            principal,
            operation,
            resource_kind,
            resource,
            requested_capabilities: CapabilitySet::EMPTY,
            offered_capabilities,
            budget: PolicyBudget::UNBOUNDED,
            context: EvaluationContext::EMPTY,
        }
    }

    /// Sets explicit requested capabilities.
    pub const fn with_requested_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.requested_capabilities = capabilities;
        self
    }

    /// Sets the requested budget.
    pub const fn with_budget(mut self, budget: PolicyBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Sets evaluation context.
    pub const fn with_context(mut self, context: EvaluationContext) -> Self {
        self.context = context;
        self
    }

    /// Returns baseline and explicit required capabilities.
    pub const fn required_capabilities(self) -> CapabilitySet {
        self.operation
            .required_capabilities(self.resource_kind)
            .union(self.requested_capabilities)
    }

    /// Returns `true` when the request should emit audit evidence.
    pub const fn requires_audit(self) -> bool {
        self.context.audit_required
            || self.operation.is_audit_critical()
            || self.resource_kind.is_audit_critical()
    }

    /// Validates request metadata before rule evaluation.
    pub fn validate(self) -> PolicyResult<()> {
        if self.request_id == INVALID_POLICY_ID {
            return Err(PolicyError::MissingField);
        }
        self.principal.validate()?;
        validate_policy_label(self.resource, MAX_POLICY_LABEL_LEN)?;
        CapabilitySet::from_bits(self.requested_capabilities.bits())?;
        CapabilitySet::from_bits(self.offered_capabilities.bits())?;
        self.budget.validate()?;
        self.context.validate()
    }
}

/// Policy evaluation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    /// Request identifier.
    pub request_id: u64,
    /// Final policy decision.
    pub decision: PolicyDecision,
    /// Stable reason label.
    pub reason: &'static str,
    /// Matched rule id, or zero when deny-by-default applied.
    pub rule_id: u64,
    /// Whether durable audit evidence must be emitted.
    pub audit_required: bool,
    /// Redaction state that should be used for exported diagnostics.
    pub redaction: RedactionState,
}

impl PolicyEvaluation {
    /// Creates an evaluation result.
    pub const fn new(
        request_id: u64,
        decision: PolicyDecision,
        reason: &'static str,
        rule_id: u64,
        audit_required: bool,
        redaction: RedactionState,
    ) -> Self {
        Self {
            request_id,
            decision,
            reason,
            rule_id,
            audit_required,
            redaction,
        }
    }

    /// Creates a deny result.
    pub const fn deny(request_id: u64, reason: &'static str, audit_required: bool) -> Self {
        Self::new(
            request_id,
            PolicyDecision::Deny,
            reason,
            INVALID_POLICY_ID,
            audit_required,
            RedactionState::SensitiveRedacted,
        )
    }

    /// Returns `true` when execution is permitted.
    pub const fn is_allowed(self) -> bool {
        self.decision.permits_execution()
    }

    /// Returns `true` when the decision must be audited.
    pub const fn requires_audit(self) -> bool {
        self.audit_required || !matches!(self.decision, PolicyDecision::Allow)
    }

    /// Validates evaluation metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.request_id == INVALID_POLICY_ID || self.reason.is_empty() {
            return Err(PolicyError::MissingField);
        }
        if self.reason.len() > MAX_POLICY_LABEL_LEN {
            return Err(PolicyError::FieldTooLong);
        }
        Ok(())
    }
}

/// Policy engine trait consumed by enforcement layers.
pub trait PolicyEngine<'a> {
    /// Evaluates a request and returns a structured decision.
    fn evaluate(&self, request: PolicyRequest<'a>) -> PolicyResult<PolicyEvaluation>;
}

/// Static dependency-free policy engine over a fixed-capacity rule set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticPolicyEngine<'a, const N: usize> {
    /// Rule set used by the engine.
    pub rules: PolicyRuleSet<'a, N>,
    /// Whether missing rules should be auditable.
    pub audit_default_denies: bool,
}

impl<'a, const N: usize> StaticPolicyEngine<'a, N> {
    /// Creates an engine from a rule set.
    pub const fn new(rules: PolicyRuleSet<'a, N>) -> Self {
        Self {
            rules,
            audit_default_denies: true,
        }
    }

    /// Sets whether default denials require audit evidence.
    pub const fn with_audit_default_denies(mut self, audit_default_denies: bool) -> Self {
        self.audit_default_denies = audit_default_denies;
        self
    }

    fn evaluate_rule(
        &self,
        request: PolicyRequest<'a>,
        rule: PolicyRule<'a>,
    ) -> PolicyResult<PolicyEvaluation> {
        let required = request
            .required_capabilities()
            .union(rule.required_capabilities);
        if !request.offered_capabilities.contains_all(required) {
            return Ok(PolicyEvaluation::deny(
                request.request_id,
                PolicyError::MissingCapability.reason(),
                true,
            ));
        }
        if !rule.max_budget.allows(request.budget) {
            return Ok(PolicyEvaluation::deny(
                request.request_id,
                "budget_exceeded",
                true,
            ));
        }
        if !request.budget.within_deadline(request.context.monotonic_ns) {
            return Ok(PolicyEvaluation::deny(
                request.request_id,
                PolicyError::DeadlineExceeded.reason(),
                true,
            ));
        }

        let decision = PolicyDecision::from_effect(rule.effect);
        let audit_required = request.requires_audit()
            || rule.audit_required
            || matches!(
                decision,
                PolicyDecision::Deny
                    | PolicyDecision::RequireEscalation
                    | PolicyDecision::RequireAudit
            );
        Ok(PolicyEvaluation::new(
            request.request_id,
            decision,
            rule.effect.label(),
            rule.id,
            audit_required,
            request.context.redaction,
        ))
    }
}

impl<'a, const N: usize> PolicyEngine<'a> for StaticPolicyEngine<'a, N> {
    fn evaluate(&self, request: PolicyRequest<'a>) -> PolicyResult<PolicyEvaluation> {
        request.validate()?;
        let Some(rule) = self.rules.select(
            request.principal,
            request.resource_kind,
            request.resource,
            request.operation,
        )?
        else {
            return Ok(PolicyEvaluation::deny(
                request.request_id,
                "default_deny",
                self.audit_default_denies || request.requires_audit(),
            ));
        };
        self.evaluate_rule(request, rule)
    }
}

/// Audit-facing record produced from a policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPolicyRecord<'a> {
    /// Request identifier.
    pub request_id: u64,
    /// Principal id.
    pub principal: &'a str,
    /// Operation label.
    pub operation: &'static str,
    /// Resource label.
    pub resource: &'a str,
    /// Final decision.
    pub decision: PolicyDecision,
    /// Stable reason label.
    pub reason: &'static str,
    /// Matched rule id.
    pub rule_id: u64,
    /// Data sensitivity.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> AuditPolicyRecord<'a> {
    /// Creates an audit-facing policy record from request and evaluation.
    pub const fn from_evaluation(request: PolicyRequest<'a>, evaluation: PolicyEvaluation) -> Self {
        Self {
            request_id: request.request_id,
            principal: request.principal.id,
            operation: request.operation.label(),
            resource: request.resource,
            decision: evaluation.decision,
            reason: evaluation.reason,
            rule_id: evaluation.rule_id,
            data_class: request.context.data_class,
            redaction: evaluation.redaction,
            trace: request.context.trace,
        }
    }

    /// Validates required audit metadata.
    pub fn validate(self) -> PolicyResult<()> {
        if self.request_id == INVALID_POLICY_ID {
            return Err(PolicyError::MissingField);
        }
        validate_policy_label(self.principal, MAX_POLICY_LABEL_LEN)?;
        validate_policy_label(self.operation, MAX_POLICY_LABEL_LEN)?;
        validate_policy_label(self.resource, MAX_POLICY_LABEL_LEN)?;
        validate_policy_label(self.reason, MAX_POLICY_LABEL_LEN)?;
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> EvaluatorDescriptor<'a> {
    /// Creates an evaluator descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
