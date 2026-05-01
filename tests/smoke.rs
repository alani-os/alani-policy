#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_policy::repository_name(), "alani-policy");
    assert!(!alani_policy::module_names().is_empty());
}
