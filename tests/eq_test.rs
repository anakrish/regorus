#[test]
fn test_value_eq() {
    use regorus::Value;
    use std::hash::{Hash, Hasher, BuildHasher};

    let builder = regorus::DefaultBuildHasher::default();

    // Test empty hasher consistency
    let ha = builder.build_hasher();
    let hb = builder.build_hasher();
    println!("empty hasher finish: {} vs {}", ha.finish(), hb.finish());
    
    // Hash just a u64
    let mut ha = builder.build_hasher();
    let mut hb = builder.build_hasher();
    42u64.hash(&mut ha);
    42u64.hash(&mut hb);
    println!("hash(42u64): {} vs {}", ha.finish(), hb.finish());
    assert_eq!(ha.finish(), hb.finish(), "Same u64 should hash the same");
    
    // Hash a Number value
    let n1 = Value::from(6);
    let n2 = Value::from(6);
    let mut ha = builder.build_hasher();
    let mut hb = builder.build_hasher();
    n1.hash(&mut ha);
    n2.hash(&mut hb);
    println!("hash(Number(6)): {} vs {}", ha.finish(), hb.finish());
    assert_eq!(ha.finish(), hb.finish(), "Same number should hash the same");
    
    // Hash Number via a fresh per-call builder (simulating hash_with_builder)
    fn hash_via_fresh_builder(v: &Value) -> u64 {
        let mut hasher = regorus::DefaultBuildHasher::default().build_hasher();
        v.hash(&mut hasher);
        hasher.finish()
    }
    let h1 = hash_via_fresh_builder(&n1);
    let h2 = hash_via_fresh_builder(&n2);
    println!("fresh_builder hash(Number(6)): {} vs {}", h1, h2);
    assert_eq!(h1, h2, "Fresh builder hashing should be deterministic");
    
    // Now the actual Set hash
    let mut s1 = Value::new_set();
    s1.as_set_mut().unwrap().insert(Value::from(6));
    let mut s2 = Value::new_set();
    s2.as_set_mut().unwrap().insert(Value::from(6));
    
    println!("s1 debug: {:?}", s1);
    println!("s2 debug: {:?}", s2);
    
    let mut h3 = builder.build_hasher();
    let mut h4 = builder.build_hasher();
    s1.hash(&mut h3);
    s2.hash(&mut h4);
    println!("Set hash: {} vs {}", h3.finish(), h4.finish());
    assert_eq!(h3.finish(), h4.finish(), "Same set should hash the same");
}
