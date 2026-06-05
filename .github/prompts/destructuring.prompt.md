---
mode: agent
---
Rego supports destructuring in many places, such as in variable assignments, function parameters, and some-in loops.

Destructing patterns can use literals, arrays, objects, var names, and the special `_` wildcard to ignore values.

**Note**: Set destructuring is not supported by Rego and should result in a compilation error.

The var names in a destructuring pattern define new local variables even if there is a rule with the same name. The new local variables shadow any outer variables with the same name.
If there is already a local variable with the same name, it is a compile-time error.

Here are some examples of destructuring in Rego:
```rego

# Destructing in function parameters
my_function([x, y, z]) {
    # x, y, z are bound to the elements of the input array
    # Input array must have exactly 3 elements
}

my_function([_, second, _]) {
    # Only the second element is bound to the variable 'second'; others are ignored
}

# Array with constants and variables
my_function([1, a, 3]) {
    # a is bound to the second element of the input array
    # Input array must be [1, <any_value>, 3]
}

# Empty array
my_function([]) {
    # Input array must be empty
}


# Destructing in object parameters
my_function({"a": a, "b": b}) {
    # a and b are bound to the values of keys "a" and "b" in the input object
    # Input object must have keys "a" and "b". Extra keys are ignored.
    # Binding can happen only for values, not keys
}

# Empty object
my_function({}) {
    # Input object must be empty
}

# Note: Set destructuring is NOT supported by Rego
# my_function({"a", b}) - This would result in a compilation error

# literals
my_function(1, 2, 3) {
    # Input must be exactly the tuple (1, 2, 3)
}

# Arbitrarily complex literals (arrays and objects only)
my_function([1, {"a": [2, 3]}, {"b": 4}, 5]) {
    # Input must match the exact structure and values
    # Note: Set patterns like {"b", 4} are not supported - use {"b": 4} instead
}

# _ wildcard
my_function([_, _, _]) {
    # Input array must have exactly 3 elements, but their values are ignored
    # _ can be used in any position where a var name can be used.
    # _ can be used multiple times in the same pattern.
}

# Arbitrarily nested patterns (arrays and objects only)
my_function([1, {"a": [_, 3]}, {"b": c}, 5]) {
    # Input must match the exact structure, with some values ignored or bound to variables
    # c is bound to the value of key "b" in the object
}

# Destructuring in some-in loops.

# For some-in loops, destructuring can be used for both the value as well as the optional key.
my_rule := v if {
    some [5, 4, a] in my_array
    # This will iterate over each element of my_array and try to match it against the pattern [5, 4, a]
    # If an element matches, a is bound to the third element of that array.
    ...
}

# Destructuring for both key and value
my_rule := v if {
    some 5, [4, a] in my_object
    # This will iterate over each key-value pair of my_object and try to match the key against 5 and the value against [4, a]
    # Note that it is nice if this sort of a loop is transformed to a direct lookup if possible since
    # the key is a fixed value.
}


# Destructuring in := assignments

# Array destructuring
my_rule := v if {
    [a,  b, _] := my_array
    # This will try to match my_array against the pattern [a, b, _]
    # If it matches, a is bound to the first element of my_array,
    # b is bound to the second element of my_array.
    # If it does not match, the rule is false.
    # The length of my_array must be exactly 3 for the match to succeed.
}

# Object destructuring
my_rule := v if {
    {"a": a, "b": 2} := my_object
    # This will try to match my_object against the pattern {"a": a, "b": 2}
    # If it matches, a is bound to the value of key "a" in my_object
    # If it does not match, the rule is false.
}

# Set destructuring is NOT supported
# {"a", b} := my_set - This would result in a compilation error

# Compile error
my_rule := v if {
    [1, 2, a] := my_array
    # Compile error since literals cannot be used.
    [a+b, a] := my_other_array
    # Compile error since expressions other than var, set and object patterns cannot  be used.
    # Technically, what happens is that a+b, 1 etc are bound to some values in the RHS
    # But since we are using := which introduces variables, lhs cannot be expressions other that don't introduce new variables.
    # Note that array and object patterns can be used since they can introduce new variables.
    # Set patterns are not supported by Rego.
}

# Destructruring in assignments using =
my_rule := v if {
    [1, 2, a] = my_array
    # This will try to match my_array against the pattern [1, 2, a]
    # Note that literals and other expresisons can be used on the lhs of =
}

# Destrucuring and prior variables
my_rule := v if {
    a := 5
    [1,2,a] = my_array
    # This will try to match my_array against the pattern [1, 2, a]
    # The a in the pattern refers to the variable defined earlier in the rule
    # and doesn't introduce a new variable.
}

# Destructuring can also happen in rhs.
# The way to detect this is to see if the rhs can be a pattern expression that defines new variables.
my_rule := v if {
    a := 5
    my_array = [1,2,a]
    # This will try to match my_array against the pattern [1, 2, a]
    # The a in the pattern refers to the variable defined earlier in the rule
    # and doesn't introduce a new variable.
}


# There is more complex destructuring with = assignment where both lhs and rhs can have patterns. We will tackle that later.


```

The way to implement destructuring in the Rego compiler is to recursively walk the destructuring pattern and generate code to extract and bind each variable and also to assert the necessary constraints for literals and structure (e,g., array length, object keys, literal values).

The value being destructured is typically in a register, and the generated code will use instructions to access elements by index (for arrays) and by key (for objects). Set destructuring is not supported by Rego and should result in compilation errors.


Implement the destructuring logic in the compiler. Write the code in rvm/compiler/destructuring.rs, by writing an impl Compiler block and any other necessary code.
Use ThisError for error handling. Keep code minimal. Refactor and reuse existing code as much as possible.

Add yaml tests in tests/compiler/destructuring.yaml to cover all the above cases, including error cases.