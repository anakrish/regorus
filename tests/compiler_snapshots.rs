use prettydiff::text::diff_lines;
use regorus::rvm::compiler::Compiler;
use regorus::rvm::program::{generate_assembly_listing, AssemblyListingConfig};
use regorus::Engine;
use std::sync::Arc;

fn compile_policy(policy: &str, entrypoint: &str) -> anyhow::Result<String> {
    let mut engine = Engine::new();
    engine.add_policy("policy.rego".to_string(), policy.to_string())?;

    let entry: Arc<str> = entrypoint.to_string().into();
    let compiled = engine.compile_with_entrypoint(&entry)?;
    let program = Compiler::compile_from_policy(&compiled, &[entrypoint])?;

    let listing = generate_assembly_listing(&program, &AssemblyListingConfig::default());
    Ok(listing)
}

#[test]
fn snapshot_simple_allow_policy() -> anyhow::Result<()> {
    let policy = r#"
        package example
        import rego.v1

        default allow := false

        allow if {
            input.user == "alice"
        }

        allow if {
            input.team == "blue"
            input.approved
        }
    "#;

    let listing = compile_policy(policy, "data.example.allow")?;
    let expected = include_str!("compiler_snapshots/simple_allow_policy.asm");

    if listing.trim() != expected.trim() {
        let diff = diff_lines(expected.trim(), listing.trim());
        panic!("Assembly snapshot mismatch:\n{}", diff);
    }

    Ok(())
}
