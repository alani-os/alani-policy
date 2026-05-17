use alani_policy::{
    policy_catalog, Capability, CapabilityGrant, CapabilityScope, CapabilitySet, CapabilityTable,
    DataClass, EvaluationContext, OperationKind, PolicyBudget, PolicyBundle, PolicyDecision,
    PolicyEffect, PolicyEngine, PolicyError, PolicyRequest, PolicyRule, PolicyRuleSet, Principal,
    PrincipalKind, RedactionState, ResourceKind, SandboxOperation, SandboxProfile, SandboxRequest,
    SandboxResource, SandboxResourceSet, StaticPolicyEngine, TraceContext, POLICY_SCHEMA_VERSION,
};

fn kernel() -> Principal<'static> {
    Principal::new(PrincipalKind::Kernel, "kernel")
}

fn runtime() -> Principal<'static> {
    Principal::new(PrincipalKind::Runtime, "runtime:init")
}

fn agent() -> Principal<'static> {
    Principal::new(PrincipalKind::Agent, "agent:alpha")
}

#[test]
fn repository_identity_and_catalog_are_stable() {
    let info = alani_policy::component_info();
    assert_eq!(alani_policy::repository_name(), "alani-policy");
    assert_eq!(info.repository, "alani-policy");
    assert_eq!(info.status, alani_policy::ComponentStatus::Experimental);
    assert_eq!(
        alani_policy::module_names(),
        &["capability", "rules", "evaluator", "sandbox"]
    );
    assert_eq!(policy_catalog().validate(), Ok(()));
    assert_eq!(policy_catalog().schema_version, POLICY_SCHEMA_VERSION);
    assert!(policy_catalog().features & alani_policy::POLICY_FEATURE_SANDBOX != 0);
}

#[test]
fn declarative_labels_map_to_public_policy_types() {
    assert_eq!(
        PrincipalKind::from_label("agent"),
        Some(PrincipalKind::Agent)
    );
    assert_eq!(ResourceKind::from_label("model"), Some(ResourceKind::Model));
    assert_eq!(
        OperationKind::from_label("infer"),
        Some(OperationKind::Infer)
    );
    assert_eq!(PolicyEffect::from_label("allow"), Some(PolicyEffect::Allow));
    assert_eq!(
        PolicyDecision::from_label("deny"),
        Some(PolicyDecision::Deny)
    );
    assert_eq!(
        CapabilitySet::named("cognition.infer"),
        Some(CapabilitySet::single(Capability::CognitionInfer))
    );

    let rule = PolicyRule::from_labels(42, "allow_from_labels", "allow", "model", "infer")
        .unwrap()
        .for_principal_kind(PrincipalKind::Agent);
    assert_eq!(rule.effect, PolicyEffect::Allow);
    assert!(rule.matches(
        agent(),
        ResourceKind::Model,
        "model:any",
        OperationKind::Infer
    ));
    assert_eq!(
        PolicyRule::from_labels(43, "bad_rule", "permit", "model", "infer").unwrap_err(),
        PolicyError::InvalidRule
    );
    assert_eq!(
        alani_policy::validate_policy_label("bad label", 128),
        Err(PolicyError::InvalidLabel)
    );
}

#[test]
fn policy_bundle_contract_validates_schema_rules_and_profiles() {
    let rules = [PolicyRule::new(
        1,
        "allow_mock_model",
        PolicyEffect::Allow,
        ResourceKind::Model,
        OperationKind::Infer,
    )
    .for_principal_kind(PrincipalKind::Agent)
    .for_resource("model:mock")];
    let profiles = [SandboxProfile::new(
        1,
        "agent_model",
        PrincipalKind::Agent,
        SandboxResourceSet::single(SandboxResource::Model),
        CapabilitySet::single(Capability::CognitionInfer),
    )];

    let bundle = PolicyBundle::new("mvk.host", 1, &rules, &profiles);
    assert_eq!(bundle.validate(), Ok(()));
    let summary = bundle.summary();
    assert_eq!(summary.schema_version, POLICY_SCHEMA_VERSION);
    assert_eq!(summary.rule_count, 1);
    assert_eq!(summary.sandbox_profile_count, 1);
    assert_eq!(summary.validate(), Ok(()));

    assert_eq!(
        bundle.with_schema_version("alani.policy.v0").validate(),
        Err(PolicyError::InvalidVersion)
    );

    let duplicate_rules = [rules[0], rules[0].for_resource("model:other")];
    assert_eq!(
        PolicyBundle::new("mvk.host", 1, &duplicate_rules, &[]).validate(),
        Err(PolicyError::Duplicate)
    );
}

#[test]
fn capability_derivation_is_attenuating_and_scoped() {
    let parent_rights = CapabilitySet::single(Capability::CapabilityAdmin)
        .with(Capability::DeviceCall)
        .with(Capability::PolicyQuery);
    let parent = CapabilityGrant::new(
        1,
        kernel(),
        runtime(),
        parent_rights,
        CapabilityScope::ANY,
        1,
    );

    let child = parent
        .derive(
            2,
            agent(),
            CapabilitySet::single(Capability::DeviceCall),
            CapabilityScope::new("device", "model-accelerator"),
            2,
        )
        .unwrap();
    assert_eq!(child.rights, CapabilitySet::single(Capability::DeviceCall));
    assert!(child.scope.allows("device", "model-accelerator"));
    assert_eq!(
        child.authorize(
            CapabilitySet::single(Capability::DeviceCall),
            "device",
            "model-accelerator",
            0,
        ),
        Ok(())
    );

    let overbroad_rights = parent.derive(
        3,
        agent(),
        CapabilitySet::single(Capability::AuditQuery),
        CapabilityScope::new("audit", "security"),
        3,
    );
    assert_eq!(
        overbroad_rights.unwrap_err(),
        PolicyError::MissingCapability
    );

    let scoped_parent = CapabilityGrant::new(
        4,
        kernel(),
        runtime(),
        parent_rights,
        CapabilityScope::new("device", "camera"),
        1,
    );
    let overbroad_scope = scoped_parent.derive(
        5,
        agent(),
        CapabilitySet::single(Capability::DeviceCall),
        CapabilityScope::ANY,
        2,
    );
    assert_eq!(overbroad_scope.unwrap_err(), PolicyError::MissingCapability);
}

#[test]
fn capability_table_rejects_stale_and_revoked_authority() {
    let grant = CapabilityGrant::new(
        7,
        kernel(),
        agent(),
        CapabilitySet::single(Capability::PolicyQuery),
        CapabilityScope::new("policy", "active"),
        1,
    )
    .with_expiration(10);
    let mut table = CapabilityTable::<4>::new();
    table.add(grant).unwrap();

    assert_eq!(
        table.authorize(
            7,
            CapabilitySet::single(Capability::PolicyQuery),
            "policy",
            "active",
            5,
        ),
        Ok(())
    );
    assert_eq!(
        table.authorize(
            7,
            CapabilitySet::single(Capability::PolicyQuery),
            "policy",
            "active",
            11,
        ),
        Err(PolicyError::MissingCapability)
    );

    table.revoke(7).unwrap();
    assert_eq!(
        table.authorize(
            7,
            CapabilitySet::single(Capability::PolicyQuery),
            "policy",
            "active",
            5,
        ),
        Err(PolicyError::InvalidCapability)
    );
}

#[test]
fn evaluator_denies_by_default_and_enforces_capabilities() {
    let empty_engine = StaticPolicyEngine::<4>::new(PolicyRuleSet::new());
    let default_denied = empty_engine
        .evaluate(PolicyRequest::new(
            1,
            agent(),
            OperationKind::Infer,
            ResourceKind::Model,
            "model:mock",
            CapabilitySet::single(Capability::CognitionInfer),
        ))
        .unwrap();
    assert_eq!(default_denied.decision, PolicyDecision::Deny);
    assert_eq!(default_denied.reason, "default_deny");
    assert!(default_denied.requires_audit());

    let mut rules = PolicyRuleSet::<4>::new();
    rules
        .add_rule(
            PolicyRule::new(
                1,
                "allow_mock_model",
                PolicyEffect::Allow,
                ResourceKind::Model,
                OperationKind::Infer,
            )
            .for_principal_kind(PrincipalKind::Agent)
            .for_resource("model:mock")
            .with_max_budget(PolicyBudget::bounded(100, 4096, 1_000)),
        )
        .unwrap();
    let engine = StaticPolicyEngine::new(rules);

    let missing_capability = engine
        .evaluate(PolicyRequest::new(
            2,
            agent(),
            OperationKind::Infer,
            ResourceKind::Model,
            "model:mock",
            CapabilitySet::EMPTY,
        ))
        .unwrap();
    assert_eq!(missing_capability.decision, PolicyDecision::Deny);
    assert_eq!(missing_capability.reason, "missing_capability");

    let allowed_request = PolicyRequest::new(
        3,
        agent(),
        OperationKind::Infer,
        ResourceKind::Model,
        "model:mock",
        CapabilitySet::single(Capability::CognitionInfer),
    )
    .with_budget(PolicyBudget::bounded(10, 1024, 900))
    .with_context(EvaluationContext::new(100, TraceContext::new(1, 2)));
    let allowed = engine.evaluate(allowed_request).unwrap();
    assert_eq!(allowed.decision, PolicyDecision::Allow);
    assert_eq!(allowed.rule_id, 1);
    assert!(allowed.is_allowed());
    assert!(allowed.audit_required);
}

#[test]
fn evaluator_prefers_deny_on_equal_priority_and_validates_redaction() {
    let mut rules = PolicyRuleSet::<4>::new();
    rules
        .add_rule(
            PolicyRule::new(
                1,
                "allow_device",
                PolicyEffect::Allow,
                ResourceKind::Device,
                OperationKind::Call,
            )
            .for_principal_kind(PrincipalKind::Agent)
            .with_priority(7),
        )
        .unwrap();
    rules
        .add_rule(
            PolicyRule::new(
                2,
                "deny_device",
                PolicyEffect::Deny,
                ResourceKind::Device,
                OperationKind::Call,
            )
            .for_principal_kind(PrincipalKind::Agent)
            .with_priority(7),
        )
        .unwrap();
    let engine = StaticPolicyEngine::new(rules);
    let denied = engine
        .evaluate(PolicyRequest::new(
            4,
            agent(),
            OperationKind::Call,
            ResourceKind::Device,
            "device:camera",
            CapabilitySet::single(Capability::DeviceCall),
        ))
        .unwrap();
    assert_eq!(denied.decision, PolicyDecision::Deny);
    assert_eq!(denied.rule_id, 2);

    let bad_redaction = PolicyRequest::new(
        5,
        agent(),
        OperationKind::Query,
        ResourceKind::Policy,
        "policy:active",
        CapabilitySet::single(Capability::PolicyQuery),
    )
    .with_context(
        EvaluationContext::new(1, TraceContext::new(3, 4))
            .with_redaction(DataClass::Secret, RedactionState::Operational),
    );
    assert_eq!(
        engine.evaluate(bad_redaction).unwrap_err(),
        PolicyError::InvalidRedaction
    );
}

#[test]
fn sandbox_prevents_boundary_access_without_capabilities() {
    let device_profile = SandboxProfile::new(
        1,
        "agent_device",
        PrincipalKind::Agent,
        SandboxResourceSet::single(SandboxResource::Device),
        CapabilitySet::single(Capability::DeviceOpen),
    );

    let no_capability = SandboxRequest::new(
        agent(),
        SandboxResource::Device,
        SandboxOperation::Open,
        "device:camera",
        CapabilitySet::EMPTY,
    );
    let denied = device_profile.evaluate(no_capability).unwrap();
    assert!(!denied.is_allowed());
    assert_eq!(denied.reason, "missing_capability");
    assert!(denied.audit_required);

    let with_capability = SandboxRequest::new(
        agent(),
        SandboxResource::Device,
        SandboxOperation::Open,
        "device:camera",
        CapabilitySet::single(Capability::DeviceOpen),
    );
    let allowed = device_profile.evaluate(with_capability).unwrap();
    assert!(allowed.is_allowed());
    assert!(allowed.audit_required);

    let audit_profile = SandboxProfile::new(
        2,
        "agent_audit",
        PrincipalKind::Agent,
        SandboxResourceSet::single(SandboxResource::Audit),
        CapabilitySet::EMPTY,
    );
    let audit_query = SandboxRequest::new(
        agent(),
        SandboxResource::Audit,
        SandboxOperation::Query,
        "audit:security",
        CapabilitySet::EMPTY,
    );
    let audit_denied = audit_profile.evaluate(audit_query).unwrap();
    assert!(!audit_denied.is_allowed());
    assert_eq!(audit_denied.reason, "missing_capability");
}
