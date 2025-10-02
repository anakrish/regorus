# Quick Start Guide

## 🚀 Get Started in 3 Steps

### 1. Build the WASM Module

From this directory, run:

```bash
./build.sh
```

This will:
- Navigate to the WASM bindings directory
- Compile Rust to WebAssembly
- Copy the output to `pkg/` folder
- Take about 30-60 seconds

### 2. Start a Local Server

Choose your preferred method:

**Python (recommended):**
```bash
python3 -m http.server 8000
```

**Node.js:**
```bash
npx http-server -p 8000
```

**VS Code:**
- Install "Live Server" extension
- Right-click `index.html` → "Open with Live Server"

### 3. Open in Browser

Navigate to: http://localhost:8000

## 📝 First Steps in the Playground

1. **Load an Example**
   - Click the "Load Example..." dropdown in the top navigation
   - Select "Simple Storage Reader"
   - This loads a basic RBAC policy and evaluation context

2. **Compile the Policy**
   - Click the "🔧 Compile to RVM" button in the Policy panel
   - See the RVM bytecode instructions appear in the middle panel
   - Check the statistics: instruction count, constants, unique opcodes

3. **Evaluate the Policy**
   - Switch to the "Context" tab in the right panel
   - Click "▶️ Evaluate"
   - See the result (ALLOW or DENY) in the "Results" tab

4. **Experiment**
   - Modify the policy (change role definitions, permissions, conditions)
   - Modify the context (change principalId, action, resource properties)
   - Recompile and reevaluate to see how results change

## 🎯 Try These Examples

### Example 1: Time-Based Access
Load the "Time-Based Access" example to see how policies can restrict access based on time of day.

**Key features:**
- Uses `UtcNow()` function
- `TimeOfDayGreaterThan` and `TimeOfDayLessThan` operators
- Allows access only during business hours (8 AM - 6 PM)

### Example 2: Conditional Access
Load "Conditional Blob Access" to see attribute-based conditions.

**Key features:**
- Uses `@Resource` attribute references
- `StringStartsWith` operator
- Allows access only to containers with names starting with 'public-'

### Example 3: Complex Multi-Condition
Load "Azure Storage Full" for a realistic production scenario.

**Key features:**
- Multiple conditions with AND/OR logic
- Container name OR blob path checks
- Encryption scope requirements
- Demonstrates precedence and grouping

## 🔍 Understanding the RVM View

The middle panel shows RVM bytecode instructions:

```
0    LoadConst      2
1    StoreLocal     0
2    LoadLocal      0
3    JumpIfFalse    10
...
```

Each instruction has:
- **Line number** (left): Instruction position in the program
- **Opcode** (middle): Operation to perform (LoadConst, StoreLocal, etc.)
- **Operands** (right): Arguments to the instruction

### Common Instructions

- `LoadConst`: Load a constant value
- `StoreLocal`: Store value in local variable
- `LoadLocal`: Load value from local variable
- `JumpIfFalse`: Conditional jump
- `Call`: Call a function
- `Return`: Return from function
- `And/Or`: Logical operations

## 🐛 Troubleshooting

### "WASM module not found"

**Solution:** Run `./build.sh` to build the WASM module first.

### Build fails with "wasm-pack: command not found"

**Solution:** Install wasm-pack:
```bash
cargo install wasm-pack
```

### "cargo: command not found"

**Solution:** Install Rust toolchain from https://rustup.rs

### Browser shows CORS errors

**Solution:** Use a proper HTTP server (not file:// protocol). Try:
```bash
python3 -m http.server 8000
```

### Changes not reflected

**Solution:** 
1. Hard refresh the browser (Cmd+Shift+R on Mac, Ctrl+Shift+R on Windows)
2. Clear browser cache
3. Rebuild WASM if you changed Rust code

## 📚 Next Steps

### Learn RBAC Concepts
- Read the [README.md](README.md) for detailed documentation
- Explore all six example policies
- Try writing your own policy from scratch

### Understand RVM
- Compare bytecode between simple and complex policies
- See how conditions are compiled to instructions
- Notice optimization patterns (constant folding, jump elimination)

### Share Your Work
- Click "🔗 Share" to generate a URL with your policy and context
- Copy the link to share with colleagues
- Use for bug reports or feature requests

### Contribute
- Report issues on GitHub
- Suggest new examples
- Improve documentation
- Add new features

## 💡 Tips & Tricks

1. **Use the Validate button** before compiling to catch JSON errors early

2. **Try breaking policies** - change a condition to see how it affects compilation

3. **Compare execution times** between similar policies to understand performance

4. **Use browser DevTools** (F12) to see detailed error messages and console logs

5. **Copy RVM bytecode** to analyze offline or compare versions

6. **Bookmark example URLs** by sharing and saving the generated links

## 🎓 Educational Use

This playground is great for:
- Learning RBAC concepts
- Understanding policy evaluation
- Teaching security principles
- Debugging policy issues
- Prototyping access control
- Demonstrating to stakeholders

## 🔗 Resources

- [Main README](README.md) - Detailed documentation
- [Regorus GitHub](https://github.com/microsoft/regorus) - Source code
- [Azure RBAC Docs](https://docs.microsoft.com/azure/role-based-access-control/)
- [RVM Architecture](../../docs/) - Technical details

---

**Having issues? Check the browser console (F12) for error messages!**
