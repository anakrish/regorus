use z3::*;

fn main() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    
    // Create some basic constraints to understand the API
    let x = ast::Int::new_const(&ctx, "x");
    let y = ast::Int::new_const(&ctx, "y");
    
    let solver = Solver::new(&ctx);
    solver.assert(&x._eq(&ast::Int::from_i64(&ctx, 10)));
    solver.assert(&y.gt(&x));
    
    match solver.check() {
        SatResult::Sat => {
            println!("Satisfiable");
            if let Some(model) = solver.get_model() {
                println!("Model: {}", model);
            }
        }
        SatResult::Unsat => println!("Unsatisfiable"),
        SatResult::Unknown => println!("Unknown"),
    }
}
