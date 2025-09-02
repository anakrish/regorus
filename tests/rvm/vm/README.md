````markdown
# VM Test Suite Documentation

This directory contains the Regorus VM test suite, organized into focused test files for better maintainability and clarity.

## Test Suite Structure

### Main Test Suites (`/suites/*.yaml`)

#### `/suites/basic_instructions.yaml`
**Purpose**: Tests fundamental VM instructions
- `Load` - Loading literals into registers
- `Move` - Moving values between registers  
- `Return` - Returning values from VM execution

**Example Rego**: Simple literals and variable assignments

#### `/suites/arithmetic_operations.yaml`
**Purpose**: Tests mathematical operations
- `Add` - Addition
- `Sub` - Subtraction
- `Mul` - Multiplication
- `Div` - Division
- `Mod` - Modulo

**Example Rego**: Arithmetic expressions like `10 + 5`, `15 / 3`, `7 % 3`

#### `/suites/comparison_operations.yaml`
**Purpose**: Tests comparison and logical instructions
- `Eq` - Equality (==)
- `Ne` - Inequality (!=)
- `Lt` - Less than (<)
- `Le` - Less than or equal (<=)
- `Gt` - Greater than (>)
- `Ge` - Greater than or equal (>=)
- `And` - Logical AND
- `Or` - Logical OR
- `Not` - Logical NOT

**Example Rego**: Comparison expressions like `5 == 5`, `3 < 5`, `x > 0 && y < 10`

#### `/suites/data_structures.yaml`
**Purpose**: Tests complex data type operations
- `ArrayNew`, `ArrayPush`, `ArrayGet` - Array creation, modification, and access
- `ObjectNew`, `ObjectSet`, `ObjectGet` - Object creation, field setting, and access
- `SetNew`, `SetAdd`, `SetContains` - Set creation, element addition, and membership

**Example Rego**: Data structure creation and access like `arr[0]`, `obj.field`, `x in set`

#### `/suites/control_flow.yaml`
**Purpose**: Tests conditional execution and branching
- `AssertCondition` - Conditional assertions
- Complex conditional logic with AND/OR
- Nested conditions and value selection

**Example Rego**: Conditional expressions like `x > 5; y < 10; result := x + y`

### Loop Test Suites (`/suites/loops/*.yaml`)

#### `/suites/loops/existential.yaml`
**Purpose**: Tests existential quantification loops (`some`)
- Basic success/failure cases
- Early exit behavior
- Empty collections
- Complex conditions

**Example Rego**: `some x in [1, 2, 3]; x > 2`

#### `/suites/loops/universal.yaml`
**Purpose**: Tests universal quantification loops (`every`)
- Basic success/failure cases
- Early exit on first failure
- Empty collections (vacuously true)
- Single element edge cases

**Example Rego**: `every x in [2, 4, 6]; x % 2 == 0`

#### `/suites/loops/array_comprehensions.yaml`
**Purpose**: Tests array comprehensions
- Simple mapping transformations
- Filtering with conditions
- Empty input handling
- Single element cases

**Example Rego**: `[x * 2 | x := [1, 2, 3][_]]`

#### `/suites/loops/set_comprehensions.yaml`
**Purpose**: Tests set comprehensions
- Duplicate elimination
- Filtering with unique results
- Empty collections
- Key collision scenarios

**Example Rego**: `{x % 3 | x := [1, 2, 3, 4, 5, 6][_]}`

#### `/suites/loops/object_comprehensions.yaml`
**Purpose**: Tests object comprehensions
- Key-value pair construction
- Complex key generation
- Filtering conditions
- Key collision behavior

**Example Rego**: `{sprintf("key_%d", [i]): i * 2 | i := [1, 2, 3][_]}`

## Test Case Format

Each test case follows this structure:

```yaml
- note: test_name
  description: Human-readable description
  example_rego: "x + y"  # Rego code this instruction sequence represents
  literals:
    - 42
    - "hello"
  instructions:
    - "Load { dest: 0, literal_idx: 0 }"  # Comments explain each instruction
    - "Return { value: 0 }"
  want_result: 42
```

## Running Tests

```bash
# Run all VM test suites
cargo test vm_tests

# Run main test suites
cargo test run_vm_test_file

# Run loop test suites specifically
cargo test run_loop_test_file

# Run with output
cargo test vm_tests -- --nocapture
```

## Key Features

1. **Educational**: Each test includes `example_rego` showing corresponding Rego code
2. **Documented**: Every instruction has comments explaining its purpose
3. **Organized**: Tests grouped by functionality for easy maintenance
4. **Comprehensive**: Covers all major VM instruction categories
5. **Direct Values**: Uses `crate::Value` for clean YAML deserialization
6. **Specialized Loop Testing**: Dedicated files for different loop types with edge cases

## Loop Test Coverage

The loop test suites provide comprehensive coverage of:
- **Edge Cases**: Empty collections, single elements, early exits
- **Complex Conditions**: Modulo operations, multiple conditions, nested logic
- **Different Quantifications**: Existential (some), universal (every)
- **Comprehension Types**: Arrays, sets, objects with transformations and filters
- **Error Scenarios**: Conditions that fail, key collisions, filter elimination

````
