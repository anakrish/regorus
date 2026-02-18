// Temporary tool to dump RVM bytecode for the allowed_server policy.
use regorus::Engine;
use regorus::languages::rego::compiler::Compiler;

fn main() {
    let policy = r#"
        package example

        default allow := false

        deny := true if {
            count(violation) == 2
        }

        violation contains server.id if {
            some server in public_server
            server.protocols[_] == "http"
        }

        public_server contains server if {
            some i, j
            some server in input.servers
            server.ports[_] == input.ports[i].id
            input.ports[i].network == input.networks[j].id
            input.networks[j].public
        }
    "#;

    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".to_string(), policy.to_string())
        .unwrap();
    let ep: regorus::Rc<str> = regorus::Rc::from("data.example.deny");
    let compiled = engine.compile_with_entrypoint(&ep).unwrap();
    let program =
        Compiler::compile_from_policy(&compiled, &["data.example.deny"]).unwrap();

    println!("=== Instructions ===");
    for (i, instr) in program.instructions.iter().enumerate() {
        let span_info = program
            .instruction_spans
            .get(i)
            .and_then(|s| s.as_ref());
        let line_info = span_info
            .map(|s| format!("  [src{} line {}]", s.source_index, s.line))
            .unwrap_or_default();
        println!("  PC {:3}: {:?}{}", i, instr, line_info);
    }

    println!("\n=== Rule Infos ===");
    for (i, ri) in program.rule_infos.iter().enumerate() {
        println!(
            "  Rule {}: name={}, type={:?}, result_reg={}, num_regs={}, defs={:?}",
            i, ri.name, ri.rule_type, ri.result_reg, ri.num_registers, ri.definitions
        );
    }

    println!("\n=== Entry Points ===");
    for (name, pc) in &program.entry_points {
        println!("  {} -> PC {}", name, pc);
    }

    println!("\n=== Sources ===");
    for (i, s) in program.sources.iter().enumerate() {
        println!("  Source {}: {}", i, s.name);
    }

    println!("\n=== Loop Params ===");
    for i in 0..20u16 {
        if let Some(lp) = program.instruction_data.get_loop_params(i) {
            println!(
                "  LoopParams {}: collection=r{}, key_reg=r{}, value_reg=r{}, result_reg=r{}, body_start={}, loop_end={}, mode={:?}",
                i, lp.collection, lp.key_reg, lp.value_reg, lp.result_reg, lp.body_start, lp.loop_end, lp.mode
            );
        }
    }

    println!("\n=== Literals ===");
    for (i, lit) in program.literals.iter().enumerate() {
        println!("  Literal {}: {:?}", i, lit);
    }

    // Also run the policy concretely to see what public_server produces.
    let input_json = r#"{
        "servers": [
            {"id": "app", "protocols": ["https", "ssh"], "ports": ["p1", "p2", "p3"]},
            {"id": "ci", "protocols": ["http"], "ports": ["p1", "p2"]}
        ],
        "networks": [
            {"id": "net1", "public": false},
            {"id": "net3", "public": true}
        ],
        "ports": [
            {"id": "p1", "network": "net1"},
            {"id": "p2", "network": "net3"}
        ]
    }"#;
    engine.set_input(regorus::Value::from_json_str(input_json).unwrap());
    let ps = engine.eval_query("data.example.public_server".to_string(), false).unwrap();
    println!("\n=== public_server (concrete) ===");
    println!("{}", serde_json::to_string_pretty(&ps).unwrap());

    let violation = engine.eval_query("data.example.violation".to_string(), false).unwrap();
    println!("\n=== violation (concrete) ===");
    println!("{}", serde_json::to_string_pretty(&violation).unwrap());
}
