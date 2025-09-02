use crate::value::Value;

/// Extensions for Value to work with RVM
pub trait ValueExt {
    fn is_truthy(&self) -> bool;
    fn as_number(&self) -> Option<f64>;
    fn as_string(&self) -> Option<&str>;
    fn set_union(&self, other: &Value) -> anyhow::Result<Value>;
    fn set_intersection(&self, other: &Value) -> anyhow::Result<Value>;
    fn contains_member(&self, value: &Value) -> bool;
}

impl ValueExt for Value {
    fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Undefined => false,
            Value::Number(n) => n.as_f64() != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Array(arr) => !arr.is_empty(),
            Value::Set(set) => !set.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
        }
    }
    
    fn as_number(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(n.as_f64()),
            _ => None,
        }
    }
    
    fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_ref()),
            _ => None,
        }
    }
    
    fn set_union(&self, other: &Value) -> anyhow::Result<Value> {
        use std::rc::Rc;
        use std::collections::BTreeSet;
        
        match (self, other) {
            (Value::Set(set_a), Value::Set(set_b)) => {
                let mut result = BTreeSet::new();
                for item in set_a.iter() {
                    result.insert(item.clone());
                }
                for item in set_b.iter() {
                    result.insert(item.clone());
                }
                Ok(Value::Set(Rc::new(result)))
            }
            _ => anyhow::bail!("Union operation requires two sets"),
        }
    }
    
    fn set_intersection(&self, other: &Value) -> anyhow::Result<Value> {
        use std::rc::Rc;
        use std::collections::BTreeSet;
        
        match (self, other) {
            (Value::Set(set_a), Value::Set(set_b)) => {
                let mut result = BTreeSet::new();
                for item in set_a.iter() {
                    if set_b.contains(item) {
                        result.insert(item.clone());
                    }
                }
                Ok(Value::Set(Rc::new(result)))
            }
            _ => anyhow::bail!("Intersection operation requires two sets"),
        }
    }
    
    fn contains_member(&self, value: &Value) -> bool {
        match self {
            Value::Array(arr) => arr.contains(value),
            Value::Set(set) => set.contains(value),
            Value::Object(obj) => obj.contains_key(value),
            Value::String(s) => {
                if let Value::String(needle) = value {
                    s.contains(needle.as_ref())
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}
