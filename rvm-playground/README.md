# RVM Playground

An interactive web-based playground for the Regorus Virtual Machine (RVM). This tool allows you to write Rego policies, compile them to RVM assembly, and evaluate them with input data.

🚀 **Live Demo**: [https://anakrish.github.io/rego-virtual-machine-playground/](https://anakrish.github.io/rego-virtual-machine-playground/)

## Features

### 🚀 **Policy Development**
- **Monaco Editor Integration**: Full-featured code editor with Rego syntax highlighting
- **Real-time Compilation**: Compile policies to RVM assembly with detailed error reporting
- **Multiple Assembly Formats**: View assembly in readable or tabular format
- **Example Policies**: Pre-built examples for common authorization patterns

### 🔧 **RVM Assembly**
- **Detailed Assembly Listings**: View compiled RVM instructions with addresses, comments, and annotations
- **Instruction Analysis**: See instruction counts, literals, and entry points
- **Configurable Display**: Customize assembly listing format and verbosity
- **Copy/Export**: Copy assembly listings to clipboard

### 📊 **Evaluation Engine**
- **Interactive Evaluation**: Test policies with custom input and data
- **JSON Editors**: Separate editors for input data and policy data
- **Real-time Results**: See evaluation results immediately
- **Execution Timing**: Monitor compilation and execution performance

### 🎨 **User Experience**
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark/Light Themes**: Choose your preferred color scheme
- **Configurable Settings**: Customize editor behavior and display options
- **Tab-based Interface**: Organized workspace with input, data, and results tabs

## Architecture

### Components

1. **Policy Editor**: Monaco-based editor with Rego language support
2. **Assembly Viewer**: Displays compiled RVM assembly with syntax highlighting
3. **Data Editors**: JSON editors for input data and policy data
4. **Results Display**: Formatted output showing evaluation results
5. **WASM Integration**: Direct integration with Regorus WASM bindings

### Technology Stack

- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Editor**: Monaco Editor (VS Code editor)
- **Backend**: Regorus WASM module
- **Assembly Generation**: RVM assembly listing API
- **Styling**: Modern CSS with CSS Grid and Flexbox

## Getting Started

### Option 1: GitHub Pages (Recommended)

The playground is automatically deployed to GitHub Pages and available at:
**https://anakrish.github.io/rego-virtual-machine-playground/**

This version includes the full WASM integration and is updated automatically when changes are pushed to the main branch of the dedicated playground repository.

### Option 2: Local Development

For local development, you can serve the playground as static files:

```bash
# Navigate to the playground directory
cd rvm-playground

# Serve with Python (Python 3)
python -m http.server 8000

# Or with Node.js http-server
npx http-server -p 8000

# Or with any other static file server
```

Then open http://localhost:8000 in your browser.

> **Note**: The local version uses mock implementations. For full functionality, build the WASM module first (see Option 3).

### Option 2: WASM Module Integration

To use with the actual Regorus WASM module:

1. **Build the WASM module**:
```bash
cd ../bindings/wasm
wasm-pack build --target web --out-dir ../../rvm-playground/wasm
```

2. **Update the JavaScript**:
```javascript
// In app.js, replace the mock WASM loading with:
import init, { Engine, RegoVM, generateAssemblyListing, AssemblyConfig } from './wasm/regorusjs.js';

async loadWASM() {
    await init();
    this.wasmModule = { Engine, RegoVM, generateAssemblyListing, AssemblyConfig };
    this.updateVMStatus('WASM Loaded');
}
```

3. **Serve the files** (WASM requires a web server due to CORS restrictions)

## Usage

### Basic Workflow

1. **Write Policy**: Enter your Rego policy in the left panel
2. **Compile**: Click "Compile" to generate RVM assembly
3. **Add Data**: Enter JSON input and data in the right panel tabs
4. **Evaluate**: Click "Evaluate" to run the policy and see results

### Example Policy

```rego
package authz

# Allow admin users
allow {
    input.user.role == "admin"
}

# Allow users to access their own resources
allow {
    input.user.id == input.resource.owner
}

# Deny by default
default allow = false
```

### Example Input

```json
{
    "user": {
        "id": "alice",
        "role": "user"
    },
    "resource": {
        "id": "doc123",
        "owner": "alice"
    }
}
```

## Development

### Future Features

The playground is designed to easily accommodate future features:

- **🐛 Debugger Integration**: Step-through debugging of RVM execution
- **🔍 SMT2 Verification**: Integration with symbolic execution and verification
- **📈 Performance Profiling**: Detailed performance analysis and optimization hints
- **🔄 Live Collaboration**: Real-time collaborative policy development
- **📦 Policy Management**: Save, load, and share policies
- **🧪 Test Suites**: Automated testing of policies with multiple inputs

### Code Structure

```
rvm-playground/
├── index.html          # Main HTML structure
├── style.css          # Responsive CSS styles
├── app.js             # Main application logic
├── examples/          # Example policies and data
└── wasm/             # Generated WASM module (when built)
```

### Key Classes

- **RVMPlayground**: Main application controller
- **Monaco Integration**: Rego language support and editor setup
- **WASM Interface**: Bridge to Regorus RVM functionality
- **UI Management**: Tab switching, modals, and responsive layout

## API Reference

### WASM Bindings

The playground uses the following enhanced WASM bindings:

```javascript
// Compilation
const engine = new Engine();
engine.addPolicy('policy.rego', policyText);
const compiled = engine.compileWithEntrypoint('data.policy.allow');
const program = compiled.compileToRvmProgram(['data.policy.allow']);

// Assembly Generation
const assembly = program.getAssemblyListing('readable');
const config = new AssemblyConfig();
config.set_show_addresses(true);
const customAssembly = generateAssemblyListing(program, 'readable', config);

// Evaluation
const vm = new RegoVM();
vm.loadProgram(program);
vm.setInput('{"user": "alice"}');
vm.setData('{}');
const result = vm.execute();
```

### Assembly Formats

- **Readable**: Human-friendly with mathematical notation and detailed comments
- **Tabular**: Compact table format for quick scanning

### Configuration Options

- **Editor Settings**: Theme, word wrap, minimap visibility
- **Assembly Settings**: Address display, comment visibility
- **Evaluation Settings**: Auto-evaluation, timing display

## Deployment

### GitHub Pages Automatic Deployment

The playground is automatically deployed to GitHub Pages via GitHub Actions:

1. **Trigger**: Push to `rvm-playground` branch or changes to playground files
2. **Build Process**:
   - Sets up Rust toolchain with WASM target
   - Installs wasm-pack
   - Builds WASM module from `bindings/wasm`
   - Copies playground files to deployment directory
   - Updates JavaScript to use real WASM instead of mock
3. **Deploy**: Publishes to GitHub Pages

### Manual Deployment

To deploy to your own GitHub Pages:

1. **Fork the repository**
2. **Enable GitHub Pages** in repository settings
3. **Set source** to "GitHub Actions"
4. **Push changes** to trigger deployment

### Custom Domain

To use a custom domain:

1. Add `CNAME` file to `rvm-playground/` directory
2. Configure DNS settings
3. Enable custom domain in GitHub Pages settings

## Contributing

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Development Guidelines

- Use modern JavaScript (ES6+)
- Follow consistent code formatting
- Add comments for complex logic
- Test with multiple browsers
- Ensure responsive design works on all screen sizes

## License

This project is part of the Regorus project and follows the same license terms.