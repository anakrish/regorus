# Rego Virtual Machine (RVM) Tutorial

Welcome to the RVM Tutorial! This guide will take you from basic concepts to advanced programming patterns in the Rego Virtual Machine. By the end, you'll understand how to read, write, and debug RVM programs.

## Table of Contents

1. [Your First RVM Program](#your-first-rvm-program)
2. [Understanding Registers](#understanding-registers)
3. [Working with Data](#working-with-data)
4. [Control Flow and Conditions](#control-flow-and-conditions)
5. [Collections and Data Structures](#collections-and-data-structures)
6. [Loops and Comprehensions](#loops-and-comprehensions)
7. [Functions and Rules](#functions-and-rules)
8. [Understanding Rego Compilation](#understanding-rego-compilation)
9. [Debugging and Optimization](#debugging-and-optimization)
10. [Advanced Patterns](#advanced-patterns)

---

## Your First RVM Program

Let's start with the simplest possible RVM program - adding two numbers.

### Hello, World! (RVM Style)

**Rego Expression:** `10 + 5`

**RVM Assembly:**
```
Literals:
  0: 10
  1: 5

Instructions:
  0: Load { dest: 0, literal_idx: 0 }    # R0 = 10
  1: Load { dest: 1, literal_idx: 1 }    # R1 = 5  
  2: Add { dest: 2, left: 0, right: 1 }  # R2 = R0 + R1
  3: Return { value: 2 }                 # Return R2
```

**Step-by-step execution:**
```
Initial state: All registers = undefined
Step 1: R0 = 10, R1 = undefined, R2 = undefined
Step 2: R0 = 10, R1 = 5, R2 = undefined  
Step 3: R0 = 10, R1 = 5, R2 = 15
Step 4: Program returns 15
```

**Key Concepts:**
- **Literals table**: Constants are stored separately from instructions
- **Registers**: Temporary storage locations (R0, R1, R2, etc.)
- **Load instruction**: Moves values from literals table to registers
- **Add instruction**: Performs arithmetic on register values
- **Return instruction**: Ends execution and returns a value

### Exercise 1: Try It Yourself

Write RVM assembly for these Rego expressions:

1. `7 * 3` (multiplication)
2. `20 - 8` (subtraction)  
3. `15 / 3` (division)

<details>
<summary>Solution</summary>

1. **7 * 3:**
```
Literals: [7, 3]
Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 7
  Load { dest: 1, literal_idx: 1 }    # R1 = 3
  Mul { dest: 2, left: 0, right: 1 } # R2 = 7 * 3 = 21
  Return { value: 2 }
```

2. **20 - 8:**
```
Literals: [20, 8]  
Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 20
  Load { dest: 1, literal_idx: 1 }    # R1 = 8
  Sub { dest: 2, left: 0, right: 1 } # R2 = 20 - 8 = 12
  Return { value: 2 }
```

3. **15 / 3:**
```
Literals: [15, 3]
Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 15
  Load { dest: 1, literal_idx: 1 }    # R1 = 3  
  Div { dest: 2, left: 0, right: 1 } # R2 = 15 / 3 = 5
  Return { value: 2 }
```
</details>

---

## Understanding Registers

Registers are the heart of the RVM. Think of them as numbered boxes that hold values.

### Register Properties

- **Numbering**: R0, R1, R2, ... (up to 255 registers)
- **Type**: Each register holds a `Value` (any Rego data type)
- **Initialization**: All registers start as `undefined`
- **Scope**: Registers are local to the current execution frame

### Register Usage Patterns

**Pattern 1: Load and Use**
```
Load R0, literal[5]    # Load a constant
Use R0 in operations   # Use the loaded value
```

**Pattern 2: Compute and Store**
```
Add R2, R0, R1         # Compute R0 + R1, store in R2
Return R2              # Return the computed result
```

**Pattern 3: Move Values Around**
```
Move R1, R0            # Copy R0's value to R1
```

### Register Allocation Example

Let's trace register usage in a more complex expression: `(10 + 5) * 2`

```rego
# Rego: (10 + 5) * 2
```

**RVM Assembly:**
```
Literals: [10, 5, 2]

Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 10
  Load { dest: 1, literal_idx: 1 }    # R1 = 5
  Add { dest: 2, left: 0, right: 1 }  # R2 = 10 + 5 = 15
  Load { dest: 3, literal_idx: 2 }    # R3 = 2
  Mul { dest: 4, left: 2, right: 3 }  # R4 = 15 * 2 = 30
  Return { value: 4 }
```

**Register Trace:**
```
                R0   R1   R2   R3   R4
Initial:       und  und  und  und  und
After Load R0:  10  und  und  und  und
After Load R1:  10    5  und  und  und
After Add:      10    5   15  und  und
After Load R3:  10    5   15    2  und
After Mul:      10    5   15    2   30
Result: 30
```

### Exercise 2: Register Allocation

Given the expression `(a + b) - (c * d)` where a=10, b=5, c=3, d=4:

1. Identify all the sub-expressions
2. Plan register allocation
3. Write the RVM assembly

<details>
<summary>Solution</summary>

**Sub-expressions:**
- `a + b` (needs two registers for operands, one for result)
- `c * d` (needs two registers for operands, one for result)  
- `(a+b) - (c*d)` (needs the two previous results)

**Register Plan:**
- R0, R1: for `a + b` operands
- R2: result of `a + b`
- R3, R4: for `c * d` operands
- R5: result of `c * d`
- R6: final result

**RVM Assembly:**
```
Literals: [10, 5, 3, 4]

Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 10 (a)
  Load { dest: 1, literal_idx: 1 }    # R1 = 5 (b)
  Add { dest: 2, left: 0, right: 1 }  # R2 = a + b = 15
  Load { dest: 3, literal_idx: 2 }    # R3 = 3 (c)
  Load { dest: 4, literal_idx: 3 }    # R4 = 4 (d)
  Mul { dest: 5, left: 3, right: 4 }  # R5 = c * d = 12
  Sub { dest: 6, left: 2, right: 5 }  # R6 = 15 - 12 = 3
  Return { value: 6 }
```
</details>

---

## Working with Data

The RVM has special instructions for loading different types of data.

### Data Loading Instructions

**Load Literals:**
```
Load { dest: 0, literal_idx: 5 }    # Load from literals table
```

**Load Common Constants:**
```
LoadTrue { dest: 0 }     # R0 = true
LoadFalse { dest: 1 }    # R1 = false
LoadNull { dest: 2 }     # R2 = null
```

**Load Global Data:**
```
LoadData { dest: 0 }     # R0 = global data object
LoadInput { dest: 1 }    # R1 = global input object
```

### Data Types in RVM

The RVM works with all Rego data types:

**Primitive Types:**
- Numbers: `42`, `3.14`
- Strings: `"hello"`
- Booleans: `true`, `false`
- Null: `null`
- Undefined: `undefined`

**Collection Types:**
- Arrays: `[1, 2, 3]`
- Objects: `{"key": "value"}`
- Sets: `{1, 2, 3}`

### Example: Loading Different Data Types

**Rego:** `data.users[0].name`

This expression involves:
1. Loading the global data object
2. Accessing the "users" field
3. Indexing the array at position 0
4. Accessing the "name" field

**RVM Assembly:**
```
Literals: ["users", 0, "name"]

Instructions:
  LoadData { dest: 0 }                      # R0 = data
  Load { dest: 1, literal_idx: 0 }          # R1 = "users"
  Index { dest: 2, container: 0, key: 1 }   # R2 = data.users
  Load { dest: 3, literal_idx: 1 }          # R3 = 0
  Index { dest: 4, container: 2, key: 3 }   # R4 = data.users[0]
  Load { dest: 5, literal_idx: 2 }          # R5 = "name"
  Index { dest: 6, container: 4, key: 5 }   # R6 = data.users[0].name
  Return { value: 6 }
```

### Optimized Chained Access

For multi-level access like `data.users[0].name`, RVM provides `ChainedIndex`:

**Optimized version:**
```
Literals: ["users", 0, "name"]
Parameters:
  chained_index_params[0] = {
    dest: 1,
    root: 0, 
    path_components: [Literal(0), Literal(1), Literal(2)]
  }

Instructions:
  LoadData { dest: 0 }                    # R0 = data
  ChainedIndex { params_index: 0 }        # R1 = data.users[0].name
  Return { value: 1 }
```

### Exercise 3: Data Access

Write RVM assembly for these expressions:

1. `input.age > 18`
2. `data.config.debug == true`

<details>
<summary>Solution</summary>

1. **input.age > 18:**
```
Literals: ["age", 18]

Instructions:
  LoadInput { dest: 0 }                   # R0 = input
  Load { dest: 1, literal_idx: 0 }        # R1 = "age"
  Index { dest: 2, container: 0, key: 1 } # R2 = input.age
  Load { dest: 3, literal_idx: 1 }        # R3 = 18
  Gt { dest: 4, left: 2, right: 3 }      # R4 = input.age > 18
  Return { value: 4 }
```

2. **data.config.debug == true:**
```
Literals: ["config", "debug"]

Instructions:
  LoadData { dest: 0 }                    # R0 = data
  Load { dest: 1, literal_idx: 0 }        # R1 = "config"
  Index { dest: 2, container: 0, key: 1 } # R2 = data.config
  Load { dest: 3, literal_idx: 1 }        # R3 = "debug"
  Index { dest: 4, container: 2, key: 3 } # R4 = data.config.debug
  LoadTrue { dest: 5 }                    # R5 = true
  Eq { dest: 6, left: 4, right: 5 }      # R6 = data.config.debug == true
  Return { value: 6 }
```
</details>

---

## Control Flow and Conditions

Unlike traditional VMs, RVM doesn't use jump instructions. Instead, it uses **assertions** for control flow.

### How Assertions Work

**Key Principle:** If any assertion fails, the entire program immediately returns `undefined`.

**Assertion Instructions:**
- `AssertCondition { condition: u8 }` - Assert that register contains `true`
- `AssertNotUndefined { register: u8 }` - Assert that register is not `undefined`

### Simple Conditional Logic

**Rego:** `x > 0; y := x + 1`

This means: "If x > 0, then set y to x + 1, otherwise the whole expression is undefined"

**RVM Assembly:**
```
# Assume input.x is loaded in R0
Load { dest: 1, literal_idx: 0 }        # R1 = 0
Gt { dest: 2, left: 0, right: 1 }      # R2 = (x > 0)
AssertCondition { condition: 2 }       # Assert R2 is true, fail if not
Load { dest: 3, literal_idx: 1 }       # R3 = 1
Add { dest: 4, left: 0, right: 3 }     # R4 = x + 1
Return { value: 4 }
```

**Execution Flow:**
```
If x = 5:
  R2 = true → assertion passes → continue → return 6

If x = -1:
  R2 = false → assertion fails → return undefined immediately
```

### Multiple Conditions

**Rego:** `x > 0; x < 100; y := x * 2`

**RVM Assembly:**
```
# R0 = x (from input)
Load { dest: 1, literal_idx: 0 }        # R1 = 0  
Gt { dest: 2, left: 0, right: 1 }      # R2 = (x > 0)
AssertCondition { condition: 2 }       # Assert x > 0

Load { dest: 3, literal_idx: 1 }       # R3 = 100
Lt { dest: 4, left: 0, right: 3 }      # R4 = (x < 100)  
AssertCondition { condition: 4 }       # Assert x < 100

Load { dest: 5, literal_idx: 2 }       # R5 = 2
Mul { dest: 6, left: 0, right: 5 }     # R6 = x * 2
Return { value: 6 }
```

### Handling Undefined Values

**Rego:** `input.user.name`

If `input.user` doesn't exist, this should return `undefined`, not crash.

**RVM Assembly:**
```
LoadInput { dest: 0 }                    # R0 = input
Load { dest: 1, literal_idx: 0 }         # R1 = "user"
Index { dest: 2, container: 0, key: 1 }  # R2 = input.user (might be undefined)
AssertNotUndefined { register: 2 }       # Fail if undefined
Load { dest: 3, literal_idx: 1 }         # R3 = "name"  
Index { dest: 4, container: 2, key: 3 }  # R4 = input.user.name
Return { value: 4 }
```

### Exercise 4: Conditional Logic

Write RVM assembly for these Rego expressions:

1. `input.age >= 21; "adult"`
2. `input.score > 80; input.score < 90; "B grade"`

<details>
<summary>Solution</summary>

1. **input.age >= 21; "adult":**
```
Literals: ["age", 21, "adult"]

Instructions:
  LoadInput { dest: 0 }                   # R0 = input
  Load { dest: 1, literal_idx: 0 }        # R1 = "age"
  Index { dest: 2, container: 0, key: 1 } # R2 = input.age
  Load { dest: 3, literal_idx: 1 }        # R3 = 21
  Ge { dest: 4, left: 2, right: 3 }      # R4 = input.age >= 21
  AssertCondition { condition: 4 }       # Assert condition
  Load { dest: 5, literal_idx: 2 }        # R5 = "adult"
  Return { value: 5 }
```

2. **input.score > 80; input.score < 90; "B grade":**
```
Literals: ["score", 80, 90, "B grade"]

Instructions:
  LoadInput { dest: 0 }                   # R0 = input
  Load { dest: 1, literal_idx: 0 }        # R1 = "score"
  Index { dest: 2, container: 0, key: 1 } # R2 = input.score
  Load { dest: 3, literal_idx: 1 }        # R3 = 80
  Gt { dest: 4, left: 2, right: 3 }      # R4 = input.score > 80
  AssertCondition { condition: 4 }       # Assert first condition
  Load { dest: 5, literal_idx: 2 }        # R5 = 90
  Lt { dest: 6, left: 2, right: 5 }      # R6 = input.score < 90
  AssertCondition { condition: 6 }       # Assert second condition
  Load { dest: 7, literal_idx: 3 }        # R7 = "B grade"
  Return { value: 7 }
```
</details>

---

## Collections and Data Structures

The RVM has specialized instructions for creating and manipulating collections.

### Creating Arrays

**Rego:** `[1, 2, 3]`

**RVM Assembly:**
```
Literals: [1, 2, 3]
Parameters:
  array_create_params[0] = {
    dest: 3,           # Result goes in R3
    elements: [0, 1, 2] # Use registers R0, R1, R2 as elements
  }

Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 1
  Load { dest: 1, literal_idx: 1 }    # R1 = 2  
  Load { dest: 2, literal_idx: 2 }    # R2 = 3
  ArrayCreate { params_index: 0 }     # R3 = [R0, R1, R2] = [1, 2, 3]
  Return { value: 3 }
```

### Creating Objects

**Rego:** `{"name": "Alice", "age": 30}`

**RVM Assembly:**
```
Literals: [
  {"name": null, "age": null},  # Template with all keys
  "Alice",                      # String value
  30                           # Number value  
]
Parameters:
  object_create_params[0] = {
    dest: 2,
    template_literal_idx: 0,      # Use template from literals[0]
    literal_key_fields: [
      (1, 0),  # "name" -> R0 (Alice)
      (2, 1)   # "age" -> R1 (30)
    ],
    fields: []  # No computed keys
  }

Instructions:
  Load { dest: 0, literal_idx: 1 }    # R0 = "Alice"
  Load { dest: 1, literal_idx: 2 }    # R1 = 30
  ObjectCreate { params_index: 0 }    # R2 = {"name": "Alice", "age": 30}
  Return { value: 2 }
```

### Creating Sets

**Rego:** `{1, 2, 3, 2}`  # Note: duplicate 2 will be removed

**RVM Assembly:**
```
Literals: [1, 2, 3, 2]
Parameters:
  set_create_params[0] = {
    dest: 4,
    elements: [0, 1, 2, 3]  # Include duplicate
  }

Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 1
  Load { dest: 1, literal_idx: 1 }    # R1 = 2
  Load { dest: 2, literal_idx: 2 }    # R2 = 3  
  Load { dest: 3, literal_idx: 3 }    # R3 = 2 (duplicate)
  SetCreate { params_index: 0 }       # R4 = {1, 2, 3} (auto-deduped)
  Return { value: 4 }
```

### Accessing Collections

**Array indexing:** `arr[0]`
```
Index { dest: 2, container: 0, key: 1 }  # R2 = R0[R1]
```

**Object field access:** `obj.field` or `obj["field"]`
```  
Index { dest: 2, container: 0, key: 1 }  # R2 = R0[R1]
```

**Set membership:** `x in set`
```
Contains { dest: 2, collection: 0, value: 1 }  # R2 = (R1 in R0)
```

**Collection size:** `count(collection)`
```
Count { dest: 1, collection: 0 }  # R1 = count(R0)
```

### Example: Working with Collections

**Rego:** `arr := [10, 20, 30]; arr[1] + 5`

**RVM Assembly:**
```
Literals: [10, 20, 30, 1, 5]
Parameters:
  array_create_params[0] = {dest: 3, elements: [0, 1, 2]}

Instructions:
  Load { dest: 0, literal_idx: 0 }      # R0 = 10
  Load { dest: 1, literal_idx: 1 }      # R1 = 20
  Load { dest: 2, literal_idx: 2 }      # R2 = 30
  ArrayCreate { params_index: 0 }       # R3 = [10, 20, 30]
  Load { dest: 4, literal_idx: 3 }      # R4 = 1 (index)
  Index { dest: 5, container: 3, key: 4 } # R5 = R3[1] = 20
  Load { dest: 6, literal_idx: 4 }      # R6 = 5
  Add { dest: 7, left: 5, right: 6 }   # R7 = 20 + 5 = 25
  Return { value: 7 }
```

### Exercise 5: Collections

Write RVM assembly for these expressions:

1. `obj := {"x": 5, "y": 10}; obj.x * obj.y`
2. `s := {1, 2, 3}; count(s)`

<details>
<summary>Solution</summary>

1. **Object creation and field access:**
```
Literals: [
  {"x": null, "y": null},  # Template
  5, 10, "x", "y"         # Values and keys
]
Parameters:
  object_create_params[0] = {
    dest: 2,
    template_literal_idx: 0,
    literal_key_fields: [(3, 0), (4, 1)],  # "x"->R0, "y"->R1  
    fields: []
  }

Instructions:
  Load { dest: 0, literal_idx: 1 }      # R0 = 5
  Load { dest: 1, literal_idx: 2 }      # R1 = 10
  ObjectCreate { params_index: 0 }      # R2 = {"x": 5, "y": 10}
  Load { dest: 3, literal_idx: 3 }      # R3 = "x"
  Index { dest: 4, container: 2, key: 3 } # R4 = obj.x = 5
  Load { dest: 5, literal_idx: 4 }      # R5 = "y"  
  Index { dest: 6, container: 2, key: 5 } # R6 = obj.y = 10
  Mul { dest: 7, left: 4, right: 6 }   # R7 = 5 * 10 = 50
  Return { value: 7 }
```

2. **Set creation and counting:**
```
Literals: [1, 2, 3]
Parameters:
  set_create_params[0] = {dest: 3, elements: [0, 1, 2]}

Instructions:
  Load { dest: 0, literal_idx: 0 }    # R0 = 1
  Load { dest: 1, literal_idx: 1 }    # R1 = 2
  Load { dest: 2, literal_idx: 2 }    # R2 = 3
  SetCreate { params_index: 0 }       # R3 = {1, 2, 3}
  Count { dest: 4, collection: 3 }    # R4 = count({1, 2, 3}) = 3
  Return { value: 4 }
```
</details>

---

## Loops and Comprehensions

Loops and comprehensions are the most complex part of RVM programming. Let's build up from simple to complex examples.

### Simple Existential Loop

**Rego:** `some x in [1, 2, 3]; x > 2`

This means: "Is there any x in [1, 2, 3] such that x > 2?" (Answer: yes, because 3 > 2)

**RVM Assembly:**
```
Literals: [1, 2, 3, 2]
Parameters:
  array_create_params[0] = {dest: 3, elements: [0, 1, 2]}
  loop_params[0] = {
    mode: Any,             # Existential quantification
    collection: 3,         # Iterate over R3 (the array)  
    key_reg: 4,           # Current index goes in R4
    value_reg: 5,         # Current value goes in R5
    result_reg: 8,        # Final result in R8
    body_start: 6,        # Loop body starts at instruction 6
    loop_end: 9           # Exit point after loop
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }     # R0 = 1
  1: Load { dest: 1, literal_idx: 1 }     # R1 = 2  
  2: Load { dest: 2, literal_idx: 2 }     # R2 = 3
  3: ArrayCreate { params_index: 0 }      # R3 = [1, 2, 3]
  4: Load { dest: 7, literal_idx: 3 }     # R7 = 2 (for comparison)
  5: LoopStart { params_index: 0 }        # Start loop
  
  # Loop body (instructions 6-8):
  6: Gt { dest: 6, left: 5, right: 7 }   # R6 = (current_value > 2)
  7: AssertCondition { condition: 6 }     # If true, loop succeeds early
  8: LoopNext { body_start: 6, loop_end: 9 } # Continue or exit
  
  9: Return { value: 8 }                  # Return loop result
```

**Execution Trace:**
```
Iteration 1: R5 = 1, R6 = (1 > 2) = false, assertion fails, continue
Iteration 2: R5 = 2, R6 = (2 > 2) = false, assertion fails, continue  
Iteration 3: R5 = 3, R6 = (3 > 2) = true, assertion passes, R8 = true, exit early
Result: true
```

### Array Comprehension

**Rego:** `[x * 2 | x in [1, 2, 3]]`

This creates a new array by doubling each element: `[2, 4, 6]`

**RVM Assembly:**
```
Literals: [1, 2, 3, 2]
Parameters:
  array_create_params[0] = {dest: 3, elements: [0, 1, 2]}
  comprehension_begin_params[0] = {
    collection_reg: 8,          # Final result goes in R8
    mode: Array                 # Array comprehension
    comprehension_end: 11       # Jump target for end
  }
  loop_params[0] = {
    mode: ForEach,              # Process all elements
    collection: 3,              # Iterate over R3
    key_reg: 4,                # Index in R4
    value_reg: 5,              # Value in R5
    result_reg: 8,             # Result accumulates in R8
    body_start: 7,             # Loop body starts at 7
    loop_end: 10               # Exit at 10
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }         # R0 = 1
  1: Load { dest: 1, literal_idx: 1 }         # R1 = 2
  2: Load { dest: 2, literal_idx: 2 }         # R2 = 3  
  3: ArrayCreate { params_index: 0 }          # R3 = [1, 2, 3]
  4: ComprehensionBegin { params_index: 0 }   # Start array comprehension
  5: Load { dest: 6, literal_idx: 3 }         # R6 = 2 (multiplier)
  6: LoopStart { params_index: 0 }            # Start loop
  
  # Loop body (instructions 7-9):
  7: Mul { dest: 7, left: 5, right: 6 }      # R7 = current_value * 2
  8: ComprehensionYield { value_reg: 7 }      # Add R7 to result array
  9: LoopNext { body_start: 7, loop_end: 10 } # Continue
  
  10: ComprehensionEnd {}                     # Finalize result in R8
  11: Return { value: 8 }                     # Return [2, 4, 6]
```

**Execution Trace:**
```
Initial: R8 = [] (empty array)
Iteration 1: R5 = 1, R7 = 1*2 = 2, R8 = [2]
Iteration 2: R5 = 2, R7 = 2*2 = 4, R8 = [2, 4]  
Iteration 3: R5 = 3, R7 = 3*2 = 6, R8 = [2, 4, 6]
Result: [2, 4, 6]
```

### Conditional Comprehension

**Rego:** `[x | x in [1, 2, 3, 4]; x % 2 == 0]`

This creates an array of even numbers: `[2, 4]`

**RVM Assembly:**
```
Literals: [1, 2, 3, 4, 2, 0]
Parameters:
  array_create_params[0] = {dest: 4, elements: [0, 1, 2, 3]}
  comprehension_begin_params[0] = {collection_reg: 9, mode: Array, comprehension_end: 15}
  loop_params[0] = {
    mode: ForEach, collection: 4, key_reg: 5, value_reg: 6,
    result_reg: 9, body_start: 9, loop_end: 14
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }         # R0 = 1
  1: Load { dest: 1, literal_idx: 1 }         # R1 = 2
  2: Load { dest: 2, literal_idx: 2 }         # R2 = 3
  3: Load { dest: 3, literal_idx: 3 }         # R3 = 4
  4: ArrayCreate { params_index: 0 }          # R4 = [1, 2, 3, 4]
  5: ComprehensionBegin { params_index: 0 }   # Start comprehension
  6: Load { dest: 7, literal_idx: 4 }         # R7 = 2 (for modulo)
  7: Load { dest: 8, literal_idx: 5 }         # R8 = 0 (for comparison)
  8: LoopStart { params_index: 0 }            # Start loop
  
  # Loop body (condition check + yield):
  9:  Mod { dest: 10, left: 6, right: 7 }    # R10 = current_value % 2
  10: Eq { dest: 11, left: 10, right: 8 }    # R11 = (R10 == 0)
  11: AssertCondition { condition: 11 }      # Skip if not even
  12: ComprehensionYield { value_reg: 6 }     # Add current value if even
  13: LoopNext { body_start: 9, loop_end: 14 } # Continue
  
  14: ComprehensionEnd {}                     # R9 = final array
  15: Return { value: 9 }
```

### Exercise 6: Loops and Comprehensions

Write RVM assembly for these expressions:

1. `every x in [2, 4, 6]; x % 2 == 0` (universal quantification)
2. `{x * x | x in [1, 2, 3]}` (set comprehension)

<details>
<summary>Solution</summary>

1. **Universal quantification:**
```
# Check if ALL elements in [2, 4, 6] are even
Literals: [2, 4, 6, 2, 0]
Parameters:
  array_create_params[0] = {dest: 3, elements: [0, 1, 2]}
  loop_params[0] = {
    mode: Every,              # Universal quantification
    collection: 3,
    key_reg: 4, value_reg: 5, result_reg: 8,
    body_start: 7, loop_end: 10
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }     # R0 = 2
  1: Load { dest: 1, literal_idx: 1 }     # R1 = 4
  2: Load { dest: 2, literal_idx: 2 }     # R2 = 6
  3: ArrayCreate { params_index: 0 }      # R3 = [2, 4, 6]
  4: Load { dest: 6, literal_idx: 3 }     # R6 = 2 (for modulo)
  5: Load { dest: 7, literal_idx: 4 }     # R7 = 0 (for comparison)
  6: LoopStart { params_index: 0 }        # Start universal loop
  
  # Loop body:
  7: Mod { dest: 9, left: 5, right: 6 }  # R9 = current_value % 2
  8: Eq { dest: 10, left: 9, right: 7 }  # R10 = (R9 == 0)
  9: AssertCondition { condition: 10 }   # If false, entire loop fails
  10: LoopNext { body_start: 7, loop_end: 11 }
  
  11: Return { value: 8 }                 # Returns true if all are even
```

2. **Set comprehension:**
```
# Create set of squares: {1, 4, 9}
Literals: [1, 2, 3]
Parameters:
  array_create_params[0] = {dest: 3, elements: [0, 1, 2]}
  comprehension_begin_params[0] = {collection_reg: 7, mode: Set, comprehension_end: 9}
  loop_params[0] = {
    mode: ForEach, collection: 3, key_reg: 4, value_reg: 5,
    result_reg: 7, body_start: 7, loop_end: 8
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }     # R0 = 1
  1: Load { dest: 1, literal_idx: 1 }     # R1 = 2
  2: Load { dest: 2, literal_idx: 2 }     # R2 = 3
  3: ArrayCreate { params_index: 0 }      # R3 = [1, 2, 3]
  4: ComprehensionBegin { params_index: 0 } # Start set comprehension
  5: LoopStart { params_index: 0 }        # Start loop
  
  # Loop body:
  6: Mul { dest: 6, left: 5, right: 5 }  # R6 = current_value * current_value
  7: ComprehensionYield { value_reg: 6 }  # Add square to set
  8: LoopNext { body_start: 6, loop_end: 9 }
  
  9: ComprehensionEnd {}                  # R7 = {1, 4, 9}
  10: Return { value: 7 }
```
</details>

---

## Functions and Rules

Functions and rules in RVM involve creating new execution contexts with isolated register windows.

### Simple Function Call

**Rego:**
```rego
multiply(x, y) := x * y

result := multiply(5, 3)
```

**RVM Assembly for `multiply` function:**
```
# Function definition
Literals: []
Instructions:
  0: Mul { dest: 0, left: 1, right: 2 }  # R0 = R1 * R2 (arg1 * arg2)
  1: Return { value: 0 }                 # Return result
```

**RVM Assembly for `multiply(5, 3)` call:**
```
Literals: [5, 3]
Parameters:
  function_call_params[0] = {
    dest: 2,              # Result goes in R2
    func_rule_index: 0,   # Function rule index
    num_args: 2,          # Two arguments
    args: [0, 1]          # R0 and R1 are arguments
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }    # R0 = 5
  1: Load { dest: 1, literal_idx: 1 }    # R1 = 3
  2: FunctionCall { params_index: 0 }    # Call multiply(R0, R1) -> R2
  3: Return { value: 2 }                 # Return result
```

**Execution Flow:**
```
1. Load arguments: R0 = 5, R1 = 3
2. Create new register window for function
3. Copy arguments to function's R1, R2
4. Execute function: R0 = R1 * R2 = 15
5. Return to caller, copy result to R2
6. Continue execution with R2 = 15
```

### Rule with Caching

**Rego:**
```rego
max_score := 100

result := max_score
```

**RVM Assembly:**
```
Literals: [100]
Instructions:
  0: Load { dest: 0, literal_idx: 0 }    # R0 = 100
  1: CallRule { dest: 1, rule_index: 0 } # Call max_score rule -> R1
  2: Return { value: 1 }                 # Return cached result
```

### Exercise 7: Functions

Write RVM assembly for this Rego code:

```rego
add_ten(x) := x + 10

result := add_ten(5)
```

<details>
<summary>Solution</summary>

**Function definition (`add_ten`):**
```
Literals: [10]
Instructions:
  0: Load { dest: 0, literal_idx: 0 }    # R0 = 10
  1: Add { dest: 2, left: 1, right: 0 } # R2 = R1 + R0 (arg + 10)
  2: Return { value: 2 }                 # Return result
```

**Function call:**
```
Literals: [5]
Parameters:
  function_call_params[0] = {
    dest: 1, func_rule_index: 0, num_args: 1, args: [0]
  }

Instructions:
  0: Load { dest: 0, literal_idx: 0 }    # R0 = 5
  1: FunctionCall { params_index: 0 }    # Call add_ten(R0) -> R1
  2: Return { value: 1 }                 # Return 15
```
</details>

---

## Understanding Rego Compilation

Let's see how different Rego constructs compile to RVM instructions.

### Simple Assignment

**Rego:** `x := 42`

**RVM:**
```
Literals: [42]
Instructions:
  Load { dest: 0, literal_idx: 0 }  # R0 = 42
  Return { value: 0 }
```

### Conditional Assignment

**Rego:** `x := 42; x > 40; result := "large"`

**RVM:**
```
Literals: [42, 40, "large"]
Instructions:
  Load { dest: 0, literal_idx: 0 }     # R0 = 42
  Load { dest: 1, literal_idx: 1 }     # R1 = 40
  Gt { dest: 2, left: 0, right: 1 }   # R2 = (42 > 40)
  AssertCondition { condition: 2 }    # Assert condition
  Load { dest: 3, literal_idx: 2 }     # R3 = "large"
  Return { value: 3 }
```

### Object Construction

**Rego:** `person := {"name": input.name, "adult": input.age >= 18}`

**RVM:**
```
Literals: [
  {"name": null, "adult": null},  # Template
  "name", "age", 18
]
Parameters:
  object_create_params[0] = {
    dest: 4,
    template_literal_idx: 0,
    literal_key_fields: [(1, 0), (2, 3)],  # "name"->R0, "adult"->R3
    fields: []
  }

Instructions:
  LoadInput { dest: 1 }                    # R1 = input
  Load { dest: 2, literal_idx: 1 }         # R2 = "name"
  Index { dest: 0, container: 1, key: 2 }  # R0 = input.name
  Load { dest: 5, literal_idx: 2 }         # R5 = "age"
  Index { dest: 6, container: 1, key: 5 }  # R6 = input.age
  Load { dest: 7, literal_idx: 3 }         # R7 = 18
  Ge { dest: 3, left: 6, right: 7 }       # R3 = input.age >= 18
  ObjectCreate { params_index: 0 }         # R4 = complete object
  Return { value: 4 }
```

### Array Comprehension with Condition

**Rego:** `evens := [x | x in numbers; x % 2 == 0]`

This shows the full pattern of comprehension compilation:

1. **Setup**: Create source collection, initialize comprehension
2. **Loop**: Iterate through each element
3. **Filter**: Apply condition (skip if false)
4. **Transform**: Apply expression to current element
5. **Collect**: Add result to comprehension collection
6. **Finalize**: Return completed collection

---

## Debugging and Optimization

### Reading RVM Assembly

When debugging RVM programs, focus on:

1. **Register flow**: Track how values move between registers
2. **Assertion points**: Where conditions can cause failure
3. **Loop boundaries**: Entry and exit points for iterations
4. **Function calls**: Register window changes

### Common Patterns

**Pattern 1: Condition Chain**
```
Load condition data
Compute condition
Assert condition
Continue with success path
```

**Pattern 2: Collection Processing**
```
Create/Load collection
Start comprehension/loop
Process each element
  - Apply condition (optional)
  - Transform element (optional)  
  - Collect result
End comprehension/loop
Return result
```

**Pattern 3: Nested Access**
```
Load root object
Index into first level
Assert not undefined (optional)
Index into second level
Assert not undefined (optional)
Continue traversal...
```

### Performance Tips

1. **Minimize register usage**: Reuse registers when values are no longer needed
2. **Use ChainedIndex**: For multi-level property access
3. **Prefer assertions over complex conditions**: Let RVM handle control flow
4. **Cache rule results**: Use CallRule for expensive computations

---

## Advanced Patterns

### Nested Comprehensions

**Rego:** `matrix := [[j | j in row] | row in rows]`

This creates nested comprehensions - an outer comprehension containing inner comprehensions.

### Conditional Rules

**Rego:**
```rego
allow {
    input.method == "GET"
    input.path == "/public"
}

allow {
    input.user.role == "admin"
}
```

Each rule body becomes a separate execution path, all contributing to the same result.

### Complex Object Patterns

**Rego:**
```rego
response := {
    "allowed": allow,
    "reason": reason,
    "metadata": {
        "timestamp": time.now_ns(),
        "version": "1.0"
    }
}
```

This shows nested object creation with computed and literal values.

---

## Summary

You've now learned the fundamentals of RVM programming:

1. **Registers**: The core storage mechanism
2. **Instructions**: How operations are encoded  
3. **Control Flow**: Assertion-based conditional execution
4. **Data Structures**: Native collection support
5. **Loops**: Iteration and comprehension patterns
6. **Functions**: Isolated execution contexts
7. **Compilation**: How Rego maps to RVM

The RVM provides a clean, efficient target for Rego compilation while maintaining the language's expressive power and semantic guarantees.

### Next Steps

- Read the complete [RVM Reference Manual](RegoVirtualMachine.md)
- Explore the implementation in `src/rvm/`
- Experiment with compilation using the RVM compiler
- Study performance characteristics of different patterns

The RVM represents a significant advancement in policy engine virtual machines, providing the foundation for high-performance Rego evaluation.