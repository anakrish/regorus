# RBAC RVM Playground

An interactive web-based playground for exploring Azure RBAC (Role-Based Access Control) policies and the Regorus Virtual Machine (RVM) bytecode compilation.

## Features

### 🎨 Three-Panel Interface
- **Policy Editor**: Write and edit RBAC policies in JSON format
- **RVM Instructions**: View compiled bytecode with statistics
- **Evaluation Panel**: Test policies with request contexts and see results

### 🔧 Core Functionality
- **Real-time Compilation**: Compile RBAC policies to RVM bytecode
- **Policy Validation**: Validate policy structure before compilation
- **Live Evaluation**: Test policies against request contexts
- **Syntax Highlighting**: CodeMirror integration for JSON editing

### 📊 Analysis Tools
- **Instruction Statistics**: See instruction count, constants, and opcode distribution
- **Execution Results**: Clear allow/deny decisions with matched roles
- **Performance Metrics**: Measure compilation and evaluation times

### 📚 Examples
Six pre-built examples demonstrating different RBAC scenarios:
1. **Simple Storage Reader** - Basic role assignment
2. **Conditional Blob Access** - Container name conditions
3. **Azure Storage Full** - Complex multi-condition policies
4. **Time-Based Access** - Time-of-day restrictions
5. **Tag-Based ABAC** - Attribute-based access control
6. **Multi-Role Complex** - Multiple roles with different scopes

### 🔗 Sharing
- Generate shareable URLs with encoded policy and context
- Copy RVM bytecode to clipboard or download as JSON

## Getting Started

### Prerequisites
- Modern web browser with WebAssembly support
- Regorus WASM module built from the parent repository

### Building the WASM Module

From the repository root:

```bash
cd bindings/wasm
wasm-pack build --target web --out-dir ../../playgrounds/rbac_rvm_playground/pkg
```

This will compile the Rust code to WebAssembly and generate the necessary JavaScript bindings in the `pkg` directory.

### Running Locally

You can use any static file server. For example:

**Python 3:**
```bash
python3 -m http.server 8000
```

**Node.js (with http-server):**
```bash
npx http-server -p 8000
```

Then open http://localhost:8000 in your browser.

### Deploying to GitHub Pages

1. Build the WASM module as described above
2. Commit all files including the `pkg` directory
3. Push to GitHub
4. Enable GitHub Pages in repository settings
5. Set source to the branch containing the playground

## Usage Guide

### Writing RBAC Policies

Policies follow this structure:

```json
{
  "version": "1.0",
  "roleDefinitions": [{
    "id": "role-id",
    "permissions": [{
      "actions": ["action1", "action2"],
      "dataActions": ["dataAction1"]
    }]
  }],
  "roleAssignments": [{
    "principalId": "user-id",
    "roleDefinitionId": "role-id",
    "scope": "/resource/scope",
    "condition": "optional condition expression"
  }]
}
```

### Condition Expressions

RBAC conditions use Azure ABAC syntax:

```
@Resource[propertyName] StringEquals 'value'
@Request[propertyName] StringStartsWith 'prefix'
ActionMatches{'Microsoft.Storage/*'}
condition1 && condition2
condition1 || condition2
!(condition)
```

### Evaluation Context

The evaluation context specifies the request being evaluated:

```json
{
  "principalId": "user-id",
  "resourceScope": "/full/resource/path",
  "action": "Microsoft.Service/action",
  "resource": {
    "propertyName": "value"
  },
  "request": {
    "propertyName": "value"
  },
  "principal": {
    "propertyName": "value"
  }
}
```

## Architecture

### Components

- **index.html** - Main page structure with three-panel layout
- **styles.css** - Dark theme styling with VS Code-inspired design
- **app.js** - Main application logic and WASM integration
- **examples.js** - Pre-built example policies and contexts
- **pkg/** - WASM module and JavaScript bindings (generated)

### WASM Integration

The playground uses the Regorus WASM module which provides:

```javascript
// Compile policy to RVM bytecode
const rvmProgram = compileRbacToRvmProgram(policyJson);

// Evaluate policy against context
const result = evaluateRbacPolicy(policyJson, contextJson);
```

## Future Enhancements

### Planned Features
- [ ] Step-through debugger with instruction highlighting
- [ ] Execution trace with call stack visualization
- [ ] VM state inspector showing registers and memory
- [ ] Performance profiler with per-instruction timing
- [ ] Visual flow diagrams for condition evaluation
- [ ] Export to different formats (Rego, OPA Bundle)
- [ ] Policy diff viewer
- [ ] Batch testing with multiple contexts
- [ ] Integration with Azure ARM templates

### Community Contributions

Contributions are welcome! Areas for improvement:
- Additional example policies
- UI/UX enhancements
- Documentation
- Test cases
- Performance optimizations

## Technical Details

### Supported Browsers
- Chrome/Edge 88+
- Firefox 79+
- Safari 14.1+

### Performance
- Policy compilation: typically < 50ms
- Policy evaluation: typically < 10ms
- RVM execution: 2-3x faster than interpreter

### Limitations
- Client-side only (no server required)
- Policy size limited by browser memory
- No external data sources (all context must be provided)

## Resources

- [Regorus GitHub Repository](https://github.com/microsoft/regorus)
- [Azure RBAC Documentation](https://docs.microsoft.com/azure/role-based-access-control/)
- [Azure ABAC Conditions](https://docs.microsoft.com/azure/role-based-access-control/conditions-overview)
- [RVM Architecture](../../docs/)

## License

This playground is part of the Regorus project and follows the same license terms.

## Credits

Built with:
- [Regorus](https://github.com/microsoft/regorus) - Rust-based policy engine
- [CodeMirror](https://codemirror.net/) - Code editor component
- [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/) - Rust-WASM integration
