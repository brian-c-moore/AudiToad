use automation_structures::{
    ActuationPass, AuditSink, Budget, Reduction, ResourceRegistry, Sequential,
};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the canonical owners' positive and refusal contracts"
)]
fn checked_owners_accept_and_refuse_the_pinned_profile() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ResourceRegistry::new();
    assert_eq!(registry.insert(0, 7), None);
    assert_eq!(registry.get(0), Some(7));
    // The public contract replaces: the application must reject this return.
    assert_eq!(registry.insert(0, 8), Some(7));
    assert_eq!(registry.get(0), Some(8));
    let mut budget = Budget::new(2);
    assert!(budget.try_allocate(2));
    assert!(!budget.try_allocate(1));
    assert_eq!(budget.allocated(), 2);
    assert!(Sequential::new(0, 6, 0).is_err());
    let mut steps = Sequential::new(1, 6, 0).map_err(|error| error.to_string())?;
    assert!(!steps.complete_step(0));
    assert!(steps.begin_step());
    assert!(!steps.begin_step());
    assert!(!steps.complete_step(6));
    assert!(steps.complete_step(1));
    assert_eq!(steps.completed(), 1);
    assert!(steps.is_done());
    assert!(!steps.begin_step());
    let mut effects = ActuationPass::new(vec![None]);
    assert!(effects.actuate(0).is_err());
    effects.allocate(0, 7).map_err(|error| error.to_string())?;
    assert!(effects.finish().is_err());
    effects.actuate(0).map_err(|error| error.to_string())?;
    assert!(effects.actuate(0).is_err());
    assert_eq!(effects.effect(0), Some(Some(7)));
    effects.finish().map_err(|error| error.to_string())?;
    let mut account = AuditSink::new(1);
    assert!(account.try_record(0));
    assert!(!account.try_record(1));
    assert_eq!(
        account
            .record(0)
            .ok_or("audit record 0 is missing")?
            .operation,
        0
    );
    assert!(account.validate());
    let mut total = Reduction::new(vec![1, 0, 1]).map_err(|error| error.to_string())?;
    while !total.is_complete() {
        total.process_next().map_err(|error| error.to_string())?;
    }
    assert_eq!(total.result(), 2);
    assert!(total.process_next().is_err());
    assert!(Reduction::new(vec![1_000_000_001]).is_err());
    Ok(())
}

#[test]
fn federation_contract_has_delegated_capacity_and_retains_it_after_release() {
    let mut owner = automation_structures::FederatedBudget::new(10, 2);
    assert!(owner.try_delegate(0, 3));
    assert!(owner.try_allocate(0, 3));
    assert!(!owner.try_allocate(0, 1));
    // Delegation may grow; the API supplies no separately configured ceiling for pool 0.
    assert!(owner.try_delegate(0, 4));
    assert_eq!(owner.pool_capacity(0), Some(7));
    assert!(owner.try_release(0, 2));
    assert_eq!(owner.pool_allocated(0), Some(1));
    assert_eq!(owner.pool_capacity(0), Some(7));
    assert_eq!(owner.master_allocated(), 7);
    assert!(!owner.try_delegate(1, 4));
    assert!(owner.try_delegate(1, 3));
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the pinned YARA parser and exact byte discrimination"
)]
fn yara_candidate_compiles_real_rules_and_discriminates_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(yara_x::VERSION, "1.20.0");
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source("rule violation { strings: $a = \"bad\" condition: $a }")?;
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(std::time::Duration::from_secs(2));
    assert_eq!(scanner.scan(b"bad")?.matching_rules().len(), 1);
    assert_eq!(scanner.scan(b"good")?.matching_rules().len(), 0);
    assert!(yara_x::Compiler::new().add_source("not a rule").is_err());
    Ok(())
}
