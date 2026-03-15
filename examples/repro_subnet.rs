use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::program::{generate_tabular_assembly_listing, AssemblyListingConfig};
use regorus::rvm::vm::RegoVM;
use regorus::{Engine, Rc, Value};

fn main() {
    let mut engine = Engine::new();
    let policy = r#"
package demo
import rego.v1

violations contains msg if {
    some subnet in input.resources
    subnet.type == "Microsoft.Network/virtualNetworks/subnets"
    nsgs := [nsg |
      some nsg in input.resources
      nsg.type == "Microsoft.Network/networkSecurityGroups"
      subnet.properties.networkSecurityGroup.id == nsg.id
    ]
    count(nsgs) != 1
    msg := sprintf("Subnet %s has no nsg", [subnet.name])
}
"#;
    engine
        .add_policy("test".to_string(), policy.to_string())
        .unwrap();

    let input_json = r#"{
      "resources": [
        {
          "type": "Microsoft.Network/virtualNetworks/subnets",
          "name": "subnetA",
          "properties": { "networkSecurityGroup": { "id": "/sub/rg/nsg-other" } }
        },
        {
          "type": "Microsoft.Network/virtualNetworks/subnets",
          "name": "subnetB",
          "properties": { "networkSecurityGroup": { "id": "/sub/rg/nsg-other" } }
        },
        {
          "type": "Microsoft.Network/networkSecurityGroups",
          "name": "nsgX",
          "id": "/sub/rg/nsgX"
        },
        {
          "type": "Microsoft.Network/networkSecurityGroups",
          "name": "nsgY",
          "id": "/sub/rg/nsgY"
        }
      ]
    }"#;
    let input = Value::from_json_str(input_json).unwrap();
    engine.set_input(input.clone());

    let entrypoint = Rc::from("data.demo.violations");
    let compiled = engine.compile_with_entrypoint(&entrypoint).unwrap();

    let program = Compiler::compile_from_policy(&compiled, &["data.demo.violations"]).unwrap();
    let config = AssemblyListingConfig::default();
    let listing = generate_tabular_assembly_listing(program.as_ref(), &config);
    println!("{listing}");

    let mut vm = RegoVM::new();
    vm.load_program(program);
    let _ = vm.set_data(Value::new_object());
    vm.set_input(input);
    let rvm_result = vm.execute().unwrap();
    println!("RVM Result: {rvm_result:?}");

    let interpreter_result = engine
        .eval_rule("data.demo.violations".to_string())
        .unwrap();
    println!("Interpreter Result: {interpreter_result:?}");

    if rvm_result != interpreter_result {
        println!("BUG: Results differ!");
    } else {
        println!("Results match.");
    }
}
