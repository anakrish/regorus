# Rego Virtual Machine (RVM) - The Definitive Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Register Model](#register-model)
4. [Program Structure](#program-structure)
5. [Instruction Set Reference](#instruction-set-reference)
6. [Execution Model](#execution-model)
7. [Control Flow](#control-flow)
8. [Data Structures](#data-structures)
9. [Function Calls](#function-calls)
10. [Loops and Comprehensions](#loops-and-comprehensions)
11. [Error Handling](#error-handling)
12. [Implementation Guidelines](#implementation-guidelines)

## Introduction

The Rego Virtual Machine (RVM) is a register-based virtual machine designed specifically for executing compiled Rego policies. It provides a stack-less, efficient execution environment that maps naturally to Rego's semantics while enabling aggressive optimization.

### Key Features

- **Register-based architecture**: No stack manipulation overhead
- **Rich instruction set**: Native support for Rego data types and operations
- **Efficient data structures**: Optimized creation and manipulation of arrays, objects, and sets
- **Built-in comprehensions**: Native support for array, set, and object comprehensions
- **Caching system**: Rule result caching for performance
- **Debugging support**: Full span information and tracing capabilities

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Rego Virtual Machine                      │
├─────────────────────┬───────────────────┬───────────────────┤
│   Register File     │   Instruction     │   Program Data    │
│                     │   Pointer (IP)    │                   │
│  R0: Value          │                   │  • Instructions   │
│  R1: Value          │   ┌─────────────┐ │  • Literals       │
│  R2: Value          │   │Current Inst │ │  • Builtin Info   │
│  R3: Value          │   │             │ │  • Rule Metadata  │
│  ...                │   └─────────────┘ │  • Entry Points   │
│  RN: Value          │                   │                   │
├─────────────────────┼───────────────────┼───────────────────┤
│   Call Stack        │   Loop Stack      │   Comprehension   │
│                     │                   │   Stack           │
│  • Rule calls       │  • Loop contexts  │  • Comprehension  │
│  • Register windows │  • Iteration vars │    contexts       │
│  • Return addresses │  • Loop counters  │  • Result accum.  │
└─────────────────────┴───────────────────┴───────────────────┘
```

## Register Model

The RVM uses a register-based execution model with the following characteristics:

### Register Properties
- **Type**: `u8` register identifiers (0-255 registers max)
- **Storage**: Each register holds a `Value` (Rego's universal value type)
- **Lifetime**: Registers are scoped to the current execution frame
- **Initialization**: All registers start as `Value::Undefined`

### Register Usage Patterns

```
Example execution trace:
R0 = Load literal[0]        // R0 = 10
R1 = Load literal[1]        // R1 = 20
R2 = Add R0, R1            // R2 = 30 (numeric addition)
R3 = ArrayCreate [R0, R1]  // R3 = [10, 20]
```

### Register Windows

Each function call or rule invocation creates a new register window:

```
Call Stack:
┌─────────────────┐
│ Rule "main"     │ ← Current frame
│ Registers 0-7   │
├─────────────────┤
│ Rule "helper"   │ ← Previous frame  
│ Registers 0-3   │
└─────────────────┘
```

## Program Structure

A compiled RVM program consists of several key components:

### Program Layout

```rust
struct Program {
    instructions: Vec<Instruction>,          // Bytecode instructions
    literals: Vec<Value>,                    // Constant value pool
    instruction_data: InstructionData,       // Complex instruction parameters
    builtin_info_table: Vec<BuiltinInfo>,    // Builtin function metadata
    entry_points: IndexMap<String, usize>,   // Named entry points
    rule_infos: Vec<RuleInfo>,              // Rule metadata
    instruction_spans: Vec<Option<SpanInfo>>, // Debug info
    num_registers: usize,                    // Register requirement
    // ... additional metadata
}
```

### Instruction Data Tables

Complex instructions store their parameters in separate tables to keep the instruction stream compact:

```
Instruction Stream:        Parameter Tables:
┌─────────────────┐       ┌─────────────────────┐
│ LOOP_START P(5) │ ───→  │ LoopStartParams[5]  │
│ LOAD R(0) L(1)  │       │  mode: Existential  │
│ BUILTIN P(12)   │ ───→  │  collection: R(3)   │
│ LOOP_NEXT       │       │  body_start: 15     │
└─────────────────┘       │  ...                │
                          └─────────────────────┘
```

## Instruction Set Reference

The RVM instruction set is organized into logical categories:

### Data Loading & Constants

#### `Load { dest: u8, literal_idx: u16 }`
Loads a literal value from the literal table into a register.

```
Before: R1 = undefined
Load R1, L[5]  // where literals[5] = "hello"
After:  R1 = "hello"
```

#### `LoadTrue/LoadFalse/LoadNull { dest: u8 }`
Optimized instructions for common constants.

```
LoadTrue R0   // R0 = true
LoadFalse R1  // R1 = false  
LoadNull R2   // R2 = null
```

#### `LoadData/LoadInput { dest: u8 }`
Loads global data or input objects.

```
LoadData R0   // R0 = global data object
LoadInput R1  // R1 = global input object
```

#### `Move { dest: u8, src: u8 }`
Copies value between registers.

```
Move R1, R0   // R1 = R0 (copy value)
```

### Arithmetic Operations

All arithmetic operations follow the pattern: `Op { dest: u8, left: u8, right: u8 }`

#### `Add/Sub/Mul/Div/Mod`

```
// Numeric operations only
R0 = 10, R1 = 3
Add R2, R0, R1    // R2 = 13
Sub R3, R0, R1    // R3 = 7
Mul R4, R0, R1    // R4 = 30
Div R5, R0, R1    // R5 = 3.333...
Mod R6, R0, R1    // R6 = 1

// Non-numeric operands result in InvalidAddition error
R7 = "hello", R8 = " world"
Add R9, R7, R8    // ERROR: InvalidAddition
```

**Semantic Rules:**
- **Numbers**: Standard arithmetic addition
- **Non-numbers**: Result in `InvalidAddition` error
- **Undefined operands**: Treated as condition failure (handled by `handle_condition`)
- **Note**: RVM Add instruction only supports numeric arithmetic. String concatenation, array concatenation, set union, and object merging require builtin function calls or specialized instructions.

### Comparison Operations

All comparisons follow: `Cmp { dest: u8, left: u8, right: u8 }`

#### `Eq/Ne/Lt/Le/Gt/Ge`

```
R0 = 10, R1 = 20
Lt R2, R0, R1     // R2 = true
Ge R3, R0, R1     // R3 = false
Eq R4, R0, R0     // R4 = true
```

**Semantic Rules:**
- Deep equality for complex types
- Cross-type comparisons follow Rego rules
- `undefined` comparisons always yield `undefined`

### Logical Operations

#### `And/Or { dest: u8, left: u8, right: u8 }`

```
R0 = true, R1 = false
And R2, R0, R1    // R2 = false
Or R3, R0, R1     // R3 = true
```

#### `Not { dest: u8, operand: u8 }`

```
R0 = true
Not R1, R0        // R1 = false
```

**Rego Truth Values:**
- `false`, `null`, `undefined` are falsy
- Everything else is truthy
- `undefined` propagates through logical operations

### Data Structure Creation

#### Array Creation

```
ArrayCreate { params_index: u16 }

Parameters:
struct ArrayCreateParams {
    dest: u8,
    elements: Vec<u8>,  // Register numbers containing elements
}
```

Example:
```
R0 = 1, R1 = 2, R2 = 3
ArrayCreate P(5)   // where params[5] = {dest: R3, elements: [R0,R1,R2]}
// Result: R3 = [1, 2, 3]
```

#### Object Creation

```
ObjectCreate { params_index: u16 }

Parameters:
struct ObjectCreateParams {
    dest: u8,
    template_literal_idx: u16,           // Template with all keys
    literal_key_fields: Vec<(u16, u8)>,  // (literal_key_idx, value_reg)
    fields: Vec<(u8, u8)>,              // (key_reg, value_reg)
}
```

Example:
```
R0 = "dynamic_key", R1 = 100
ObjectCreate P(7)
// where params[7] creates {"static": R2, "dynamic_key": 100}
```

#### Set Creation

```
SetCreate { params_index: u16 }

Parameters:
struct SetCreateParams {
    dest: u8,
    elements: Vec<u8>,  // Register numbers containing elements
}
```

### Data Access & Indexing

#### `Index { dest: u8, container: u8, key: u8 }`

Generic indexing operation for all container types:

```
R0 = {"a": 1, "b": 2}, R1 = "a"
Index R2, R0, R1      // R2 = 1

R3 = [10, 20, 30], R4 = 1
Index R5, R3, R4      // R5 = 20

R6 = {1, 2, 3}, R7 = 2
Index R8, R6, R7      // R8 = 2 (set membership)
```

#### `ChainedIndex { params_index: u16 }`

Optimized multi-level access:

```
Parameters:
struct ChainedIndexParams {
    dest: u8,
    object: u8,
    indices: Vec<u16>,  // Literal indices for chained access
}

// Equivalent to: obj.field1.field2.field3
ChainedIndex P(3)  // params[3] = {dest: R5, object: R0, indices: [L1,L2,L3]}
```

### Collection Operations

#### `Contains { dest: u8, collection: u8, value: u8 }`

Membership testing:

```
R0 = [1, 2, 3], R1 = 2
Contains R2, R0, R1   // R2 = true

R3 = {"a": 1}, R4 = "a"  
Contains R5, R3, R4   // R5 = true (key exists)

R6 = {1, 2, 3}, R7 = 4
Contains R8, R6, R7   // R8 = false
```

#### `Count { dest: u8, collection: u8 }`

Get collection size:

```
R0 = [1, 2, 3]
Count R1, R0          // R1 = 3

R2 = {"a": 1, "b": 2}
Count R3, R2          // R3 = 2

R4 = {1, 2, 3, 2}
Count R5, R4          // R5 = 3 (sets have unique elements)
```

### Control Flow & Assertions

#### `AssertCondition { condition: u8 }`

Validates that a condition is true (not false, null, or undefined):

```
R0 = true
AssertCondition R0    // Continues execution

R1 = false
AssertCondition R1    // Immediately returns undefined
```

#### `AssertNotUndefined { register: u8 }`

Ensures a register doesn't contain undefined:

```
R0 = 42
AssertNotUndefined R0 // Continues execution

R1 = undefined
AssertNotUndefined R1 // Immediately returns undefined
```

### Loops and Iteration

#### `LoopStart { params_index: u16 }`

Initiates iteration over a collection:

```
Parameters:
struct LoopStartParams {
    mode: LoopMode,           // Existential/Universal/Comprehension
    collection: u8,           // Register with collection to iterate
    key_reg: u8,             // Register for current key
    value_reg: u8,           // Register for current value  
    result_reg: u8,          // Register for accumulating result
    body_start: u16,         // Jump target for loop body
    loop_end: u16,           // Jump target after loop
}

enum LoopMode {
    Existential,    // some x in collection { ... } 
    Universal,      // every x in collection { ... }
    ArrayCompr,     // [x | x in collection; ...]
    SetCompr,       // {x | x in collection; ...}
    ObjectCompr,    // {k: v | x in collection; ...}
}
```

#### `LoopNext { body_start: u16, loop_end: u16 }`

Advances to next iteration or exits loop:

```
Loop execution flow:
┌─────────────────┐
│   LoopStart     │ ← Initialize iteration
├─────────────────┤
│   Loop Body     │ ← Process current element
│   Instructions  │
├─────────────────┤
│   LoopNext      │ ← Advance/check termination
└─────┬───────────┘
      │
      └─→ Jump to body_start (continue) or loop_end (exit)
```

### Comprehensions

#### `ComprehensionBegin { params_index: u16 }`

Starts a comprehension context:

```
Parameters:
struct ComprehensionBeginParams {
    result_reg: u8,             // Register for final result
    mode: ComprehensionMode,    // Array/Set/Object
}
```

#### `ComprehensionYield { value_reg: u8, key_reg: Option<u8> }`

Adds a value to the comprehension result:

```
Array/Set comprehension:
ComprehensionYield R0     // Add R0 to result

Object comprehension:  
ComprehensionYield R1, Some(R0)  // Add R0:R1 pair to result
```

#### `ComprehensionEnd {}`

Finalizes the comprehension and stores result.

### Function Calls

#### `BuiltinCall { params_index: u16 }`

Calls a built-in function:

```
Parameters:
struct BuiltinCallParams {
    dest: u8,
    builtin_index: u16,       // Index into builtin_info_table
    num_args: u8,
    args: [u8; 8],           // Argument registers (max 8 args)
}

// Example: count([1,2,3])
R0 = [1, 2, 3]
BuiltinCall P(5)  // params[5] = {dest: R1, builtin: "count", args: [R0]}
// Result: R1 = 3
```

#### `FunctionCall { params_index: u16 }`

Calls a user-defined function rule:

```
Parameters:
struct FunctionCallParams {
    dest: u8,
    func_rule_index: u16,     // Index of function rule
    num_args: u8,
    args: [u8; 8],           // Argument registers
}
```

#### `CallRule { dest: u8, rule_index: u16 }`

Calls a rule with caching support:

```
CallRule R0, 15   // Call rule[15], store result in R0
```

### Program Termination

#### `Return { value: u8 }`
Returns a value from the current execution context.

#### `RuleReturn {}`
Returns from rule execution (used internally).

#### `Halt {}`
Stops program execution.

## Execution Model

### Execution Loop

```rust
fn execute(program: &Program) -> Result<Value> {
    let mut registers = vec![Value::Undefined; program.num_registers];
    let mut ip = program.main_entry_point;
    
    loop {
        let instruction = &program.instructions[ip];
        
        match instruction {
            Instruction::Load { dest, literal_idx } => {
                registers[*dest as usize] = program.literals[*literal_idx as usize].clone();
                ip += 1;
            }
            
            Instruction::Add { dest, left, right } => {
                let left_val = &registers[*left as usize];
                let right_val = &registers[*right as usize];
                registers[*dest as usize] = add_values(left_val, right_val)?;
                ip += 1;
            }
            
            // ... handle other instructions
            
            Instruction::Return { value } => {
                return Ok(registers[*value as usize].clone());
            }
            
            Instruction::Halt {} => break,
        }
    }
    
    Ok(Value::Undefined)
}
```

### Undefined Propagation

The RVM follows Rego's undefined propagation semantics:

```
Instruction result = undefined → Early termination
AssertCondition(false/null/undefined) → Early termination  
AssertNotUndefined(undefined) → Early termination
```

Example:
```
R0 = undefined
R1 = 5
Add R2, R0, R1        // Undefined operand causes condition failure
                      // Program handles via handle_condition() mechanism
```

## Control Flow

### Conditional Execution

RVM doesn't have explicit conditional jump instructions. Instead, it uses assertions:

```rego
# Rego: x > 0; y := x + 1
```

Compiles to:
```
Load R0, input.x      // R0 = input.x
Load R1, 0           // R1 = 0  
Gt R2, R0, R1        // R2 = (x > 0)
AssertCondition R2   // Fail if condition is false
Load R4, 1           // R4 = 1
Add R3, R0, R4       // R3 = x + 1 (only reached if condition true)
```

### Loop Control Flow

```
Array comprehension: [x * 2 | x in arr; x > 0]

    ComprehensionBegin P(0)     // Start array comprehension
    Load R0, input.arr          // R0 = input array
    LoopStart P(1)              // Start iteration: key=R1, value=R2
↓
│   Load R3, 0                 // R3 = 0
│   Gt R4, R2, R3              // R4 = (x > 0)  
│   AssertCondition R4         // Skip if condition false
│   Load R5, 2                 // R5 = 2
│   Mul R6, R2, R5             // R6 = x * 2
│   ComprehensionYield R6      // Add to result
↓
    LoopNext body_start, end    // Continue iteration
    ComprehensionEnd            // Finalize result
```

## Data Structures

### Array Semantics

```
Creation:    ArrayCreate {dest: R0, elements: [R1, R2, R3]}
Indexing:    Index R4, R0, R5        // R4 = R0[R5]
Length:      Count R6, R0            // R6 = len(R0)
Membership:  Contains R7, R0, R8     // R7 = (R8 in R0)
```

**Index Behavior:**
- Negative indices: `undefined`
- Out-of-bounds: `undefined`
- Non-integer indices: `undefined`

### Object Semantics

```
Creation:    ObjectCreate P(5)       // Complex parameter structure
Field access: Index R1, R0, "key"   // R1 = R0.key  
Field check: Contains R2, R0, "key" // R2 = ("key" in R0.keys)
Size:        Count R3, R0            // R3 = number of keys
```

**Key Types:** Objects support any value type as keys, with string conversion for non-string keys.

### Set Semantics

```
Creation:    SetCreate {dest: R0, elements: [R1, R2, R3]}
Membership:  Contains R4, R0, R5     // R4 = (R5 in R0)
Size:        Count R6, R0            // R6 = |R0|
```

**Uniqueness:** Sets automatically deduplicate elements using Rego's deep equality.

## Function Calls

### Built-in Functions

Built-ins are resolved at compilation time and called efficiently:

```
Built-in call: count([1, 2, 3])

R0 = [1, 2, 3]
BuiltinCall P(12)   // params[12] = {builtin: "count", args: [R0], dest: R1}
// Result: R1 = 3
```

### User-Defined Functions

Function rules create new execution contexts:

```rego
# Rego function:
multiply(x, y) := x * y

# Call site:
result := multiply(5, 3)
```

Compiles to:
```
Load R0, 5
Load R1, 3
FunctionCall P(8)   // params[8] = {func_rule: "multiply", args: [R0,R1], dest: R2}
// Result: R2 = 15
```

**Parameter Passing:**
- Arguments are passed by copying register values
- New register window is created for function scope
- Return value is copied back to destination register

### Rule Calls

Rules can be called with caching for performance:

```
CallRule R0, 15     // Call rule[15], cache result, store in R0
```

**Caching Behavior:**
- First call executes rule and caches result
- Subsequent calls return cached result
- Cache invalidation on data/input changes

## Loops and Comprehensions

### Loop Types

#### Existential Quantification (`some`)

```rego
# Rego: some x in arr; x > 0
```

```
LoopStart P(0)      // mode: Existential, result_reg: R5
│ Gt R3, R2, R1     // R2 = current value, R1 = 0
│ AssertCondition R3 // If true, set R5 = true and exit loop early
LoopNext body, end
// R5 = true if any element > 0, false otherwise
```

#### Universal Quantification (`every`)

```rego  
# Rego: every x in arr; x > 0
```

```
LoopStart P(1)      // mode: Universal, result_reg: R5  
│ Gt R3, R2, R1     // R2 = current value, R1 = 0
│ AssertCondition R3 // If false, set R5 = false and exit loop early
LoopNext body, end
// R5 = true if all elements > 0, false otherwise
```

### Comprehension Types

#### Array Comprehensions

```rego
# Rego: [x * 2 | x in arr; x > 0]
```

```
ComprehensionBegin P(0)    // mode: Array, result_reg: R10
LoopStart P(1)             // collection: R0, value_reg: R2
│ Gt R3, R2, R1           // x > 0 
│ AssertCondition R3       // Skip if false
│ Mul R4, R2, R5          // x * 2 (R5 = 2)
│ ComprehensionYield R4    // Add to array result
LoopNext body, end
ComprehensionEnd           // R10 = final array
```

#### Set Comprehensions

```rego
# Rego: {x | x in arr; x > 0}
```

```
ComprehensionBegin P(0)    // mode: Set, result_reg: R10
LoopStart P(1)             // collection: R0, value_reg: R2
│ Gt R3, R2, R1           // x > 0
│ AssertCondition R3       // Skip if false  
│ ComprehensionYield R2    // Add to set result (automatic dedup)
LoopNext body, end
ComprehensionEnd           // R10 = final set
```

#### Object Comprehensions

```rego
# Rego: {k: v | some k, v in obj; v > 0}
```

```
ComprehensionBegin P(0)    // mode: Object, result_reg: R10
LoopStart P(1)             // collection: R0, key_reg: R2, value_reg: R3
│ Gt R4, R3, R1           // v > 0 (R1 = 0)  
│ AssertCondition R4       // Skip if false
│ ComprehensionYield R3, Some(R2)  // Add k:v pair
LoopNext body, end
ComprehensionEnd           // R10 = final object
```

### Nested Comprehensions

The RVM supports arbitrary nesting using comprehension stacks:

```rego
# Rego: [[y | y in inner] | inner in outer]
```

```
ComprehensionBegin P(0)      // Outer array comprehension
LoopStart P(1)               // Iterate over outer
│ ComprehensionBegin P(2)    // Inner array comprehension  
│ LoopStart P(3)             // Iterate over inner
│ │ ComprehensionYield R5    // Add y to inner result
│ LoopNext inner_body, inner_end
│ ComprehensionEnd           // Complete inner comprehension
│ ComprehensionYield R10     // Add inner result to outer
LoopNext outer_body, outer_end
ComprehensionEnd             // Complete outer comprehension
```

## Error Handling

### Undefined Semantics

The RVM implements Rego's three-valued logic (true, false, undefined):

```
Operations on undefined:
- arithmetic: undefined operands trigger condition failure via handle_condition()
- comparisons: undefined operands trigger condition failure via handle_condition()
- logical: undefined && true = undefined (logical ops don't fail on undefined)
- assertions: AssertCondition(undefined) = fail
```

### Error Propagation

```
Error types and handling:
1. VmError::AssertionFailed → Return undefined
2. VmError::InstructionLimitExceeded → Return error
3. VmError::InvalidOperation → Return undefined
4. Runtime panics → Return error
```

### Debugging Support

Every instruction can have associated span information:

```rust
struct SpanInfo {
    source_index: usize,    // Which source file
    line: usize,           // Line number (1-based)  
    column: usize,         // Column number (1-based)
    length: usize,         // Span length
}
```

This enables:
- Precise error location reporting
- Step-by-step debugging
- Profiling and performance analysis
- Coverage reporting

## Implementation Guidelines

### Register Allocation

Efficient register allocation is crucial for performance:

```rust
// Recommended allocation strategy:
struct RegisterAllocator {
    next_register: u8,
    free_registers: Vec<u8>,
    max_registers: u8,
}

impl RegisterAllocator {
    fn alloc(&mut self) -> u8 {
        self.free_registers.pop()
            .unwrap_or_else(|| {
                let reg = self.next_register;
                self.next_register += 1;
                self.max_registers = self.max_registers.max(self.next_register);
                reg
            })
    }
    
    fn free(&mut self, reg: u8) {
        self.free_registers.push(reg);
    }
}
```

### Instruction Encoding

Instructions should be compactly encoded for cache efficiency:

```rust
// Compact instruction representation:
#[repr(C)]
pub enum Instruction {
    // Use u8 for register IDs (max 256 registers)
    Load { dest: u8, literal_idx: u16 },     // 4 bytes
    Add { dest: u8, left: u8, right: u8 },   // 4 bytes
    // Use parameter tables for complex instructions
    LoopStart { params_index: u16 },         // 3 bytes + padding
}
```

### Optimization Opportunities

#### Dead Code Elimination
```
R0 = Load 5
R1 = Load 10      ← Dead (R1 never used)
R2 = Add R0, R0
Return R2
```

#### Register Reuse
```
Original:
R0 = Load 5
R1 = Load 10  
R2 = Add R0, R1
Return R2

Optimized:
R0 = Load 5
R1 = Load 10
R0 = Add R0, R1   ← Reuse R0 instead of R2
Return R0
```

#### Constant Folding
```
Original:
R0 = Load 5
R1 = Load 10
R2 = Add R0, R1

Optimized:
R2 = Load 15      ← Computed at compile time
```

#### Instruction Fusion
```  
Original:
Load R0, 0
Gt R1, R2, R0

Optimized:
GtZero R1, R2     ← Specialized instruction
```

### Memory Management

The RVM should minimize allocations during execution:

```rust
// Pre-allocate collections:
struct VM {
    registers: Vec<Value>,           // Pre-sized to program needs
    call_stack: Vec<CallFrame>,      // Reused across calls
    loop_stack: Vec<LoopContext>,    // Reused across loops
    comprehension_stack: Vec<ComprehensionContext>,
}

// Reuse Value objects where possible:
enum Value {
    // Use Rc for sharing immutable values
    Object(Rc<BTreeMap<Value, Value>>),
    Array(Rc<Vec<Value>>),
    Set(Rc<BTreeSet<Value>>),
    // ...
}
```

### Performance Considerations

#### Hot Path Optimization
- Inline simple operations (Load, Move, arithmetic)
- Use jump tables for instruction dispatch
- Minimize memory allocations in loops
- Cache builtin function pointers

#### Instruction Limits
```rust
const MAX_INSTRUCTIONS: usize = 1_000_000;

fn execute_with_limit(&mut self) -> Result<Value> {
    let mut instruction_count = 0;
    
    loop {
        instruction_count += 1;
        if instruction_count > MAX_INSTRUCTIONS {
            return Err(VmError::InstructionLimitExceeded { 
                limit: MAX_INSTRUCTIONS 
            });
        }
        
        // Execute instruction...
    }
}
```

#### Profiling Support
```rust
struct ExecutionStats {
    instruction_counts: HashMap<String, u64>,
    register_usage: Vec<u64>,
    function_call_counts: HashMap<String, u64>,
    total_instructions: u64,
}
```

### Testing Guidelines

#### Unit Tests for Instructions
```rust
#[test]
fn test_add_instruction() {
    let mut vm = VM::new();
    vm.registers[0] = Value::from(5);
    vm.registers[1] = Value::from(10);
    
    vm.execute_instruction(&Instruction::Add { 
        dest: 2, left: 0, right: 1 
    }).unwrap();
    
    assert_eq!(vm.registers[2], Value::from(15));
}
```

#### Integration Tests for Programs
```rust
#[test]  
fn test_array_comprehension() {
    let program = compile_rego(r#"
        result := [x * 2 | x in [1, 2, 3]; x > 1]
    "#).unwrap();
    
    let mut vm = VM::new();
    let result = vm.execute(&program).unwrap();
    
    assert_eq!(result, Value::from(vec![4, 6]));
}
```

#### Property-Based Testing
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_arithmetic_commutativity(a in any::<i64>(), b in any::<i64>()) {
        let program1 = compile_add_expr(a, b);
        let program2 = compile_add_expr(b, a);
        
        let result1 = execute_program(&program1);
        let result2 = execute_program(&program2);
        
        prop_assert_eq!(result1, result2);
    }
}
```

### Conclusion

The Rego Virtual Machine provides a robust, efficient execution environment for compiled Rego policies. Its register-based architecture, rich instruction set, and native support for Rego's data types and semantics make it an ideal target for high-performance policy evaluation.

Key strengths:
- **Performance**: Register-based design eliminates stack overhead
- **Expressiveness**: Native support for Rego constructs
- **Debuggability**: Complete span information and tracing
- **Extensibility**: Clean instruction set for adding new operations
- **Correctness**: Faithful implementation of Rego semantics

For implementers, focus on:
1. Efficient register allocation
2. Compact instruction encoding  
3. Minimal runtime allocations
4. Comprehensive testing
5. Performance monitoring

The RVM represents the state of the art in policy engine virtual machines, providing the foundation for the next generation of high-performance Rego implementations.
