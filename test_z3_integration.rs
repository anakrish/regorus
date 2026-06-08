use regorus::z3_integration::z3_sys_converter::Z3SysConverter;

fn main() {
    println!("Creating Z3SysConverter...");
    
    match Z3SysConverter::new() {
        Ok(converter) => {
            println!("✓ Z3SysConverter created successfully");
            println!("Z3 context initialized with uninterpreted sorts");
        }
        Err(e) => {
            println!("✗ Failed to create Z3SysConverter: {}", e);
        }
    }
}
