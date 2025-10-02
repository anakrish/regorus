// Main Application Logic
class RbacPlayground {
    constructor() {
        this.wasmModule = null;
        this.policyEditor = null;
        this.contextEditor = null;
        this.compiledProgram = null;
        this.executionState = {
            pc: 0,
            running: false,
            trace: [],
            vmState: {}
        };
        
        this.init();
    }

    async init() {
        await this.loadWasm();
        this.initEditors();
        this.initEventListeners();
        this.loadExample('simple');
        this.updateStatus('Ready', 'success');
    }

    async loadWasm() {
        try {
            this.updateStatus('Loading WASM module...', 'warning');
            
            // Dynamic import for ES6 modules (browser context)
            if (typeof document !== 'undefined') {
                try {
                    // Import the WASM module
                    const wasmModule = await import('./pkg/regorusjs.js');
                    await wasmModule.default();
                    this.wasmModule = wasmModule;
                    this.updateStatus('WASM module loaded successfully ✓', 'success');
                    return;
                } catch (importError) {
                    console.warn('ES6 import failed, trying script tag approach:', importError);
                    // Fall back to showing build instructions
                    this.showBuildInstructions();
                    return;
                }
            }
            
            // Node.js context (for testing)
            if (typeof require !== 'undefined') {
                this.wasmModule = require('./pkg/regorusjs.js');
                await this.wasmModule.default();
                this.updateStatus('WASM module loaded successfully ✓', 'success');
            }
        } catch (error) {
            console.error('Failed to load WASM module:', error);
            this.showBuildInstructions();
        }
    }

    showBuildInstructions() {
        this.updateStatus('WASM module not found. Please build first.', 'error');
        
        // Show instructions in the RVM panel
        const instructions = document.getElementById('rvmInstructions');
        if (!instructions) return;
        
        instructions.innerHTML = `
            <div style="padding: 2rem; color: var(--text-primary);">
                <h3 style="color: var(--accent-yellow); margin-bottom: 1rem;">⚠️ WASM Module Not Found</h3>
                <p style="margin-bottom: 1rem;">The playground requires the Regorus WASM module to be built first.</p>
                
                <h4 style="color: var(--accent-green); margin-top: 1.5rem; margin-bottom: 0.5rem;">Build Instructions:</h4>
                <ol style="margin-left: 1.5rem; line-height: 1.8;">
                    <li>Run the build script: <code style="background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 3px;">./build.sh</code></li>
                    <li>Or manually: <code style="background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 3px;">cd ../../bindings/wasm && wasm-pack build --target web --out-dir ../../playgrounds/rbac_rvm_playground/pkg</code></li>
                    <li>Refresh this page</li>
                </ol>
                
                <h4 style="color: var(--accent-green); margin-top: 1.5rem; margin-bottom: 0.5rem;">Requirements:</h4>
                <ul style="margin-left: 1.5rem; line-height: 1.8;">
                    <li>Rust toolchain installed</li>
                    <li>wasm-pack: <code style="background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 3px;">cargo install wasm-pack</code></li>
                </ul>
                
                <p style="margin-top: 1.5rem; color: var(--text-secondary); font-size: 0.875rem;">
                    Without the WASM module, you can still view the interface and examples, but compilation and evaluation will not work.
                </p>
            </div>
        `;
    }

    initEditors() {
        // Initialize CodeMirror for policy editor
        const policyTextarea = document.getElementById('policyEditor');
        this.policyEditor = CodeMirror.fromTextArea(policyTextarea, {
            mode: { name: "javascript", json: true },
            theme: 'eclipse',
            lineNumbers: true,
            matchBrackets: true,
            autoCloseBrackets: true,
            indentUnit: 2,
            tabSize: 2,
            lineWrapping: false
        });

        // Initialize CodeMirror for context editor
        const contextTextarea = document.getElementById('contextEditor');
        this.contextEditor = CodeMirror.fromTextArea(contextTextarea, {
            mode: { name: "javascript", json: true },
            theme: 'eclipse',
            lineNumbers: true,
            matchBrackets: true,
            autoCloseBrackets: true,
            indentUnit: 2,
            tabSize: 2,
            lineWrapping: false
        });
    }

    initEventListeners() {
        // Example selector
        document.getElementById('exampleSelector').addEventListener('change', (e) => {
            if (e.target.value) {
                this.loadExample(e.target.value);
            }
        });

        // Compile button
        document.getElementById('compileBtn').addEventListener('click', () => {
            this.compilePolicy();
        });

        // Validate button
        document.getElementById('validateBtn').addEventListener('click', () => {
            this.validatePolicy();
        });

        // Evaluation button
        document.getElementById('evalBtn')?.addEventListener('click', () => {
            this.evaluatePolicy();
        });

        // Step/Run/Reset buttons (may not exist in current UI)
        document.getElementById('stepBtn')?.addEventListener('click', () => {
            this.stepExecution();
        });

        document.getElementById('runBtn')?.addEventListener('click', () => {
            this.runExecution();
        });

        document.getElementById('resetBtn')?.addEventListener('click', () => {
            this.resetExecution();
        });

        // Share button
        document.getElementById('shareBtn').addEventListener('click', () => {
            this.showShareModal();
        });

        // Help button
        document.getElementById('helpBtn').addEventListener('click', () => {
            this.showHelpModal();
        });

        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Modal close buttons
        document.querySelectorAll('.close').forEach(closeBtn => {
            closeBtn.addEventListener('click', (e) => {
                e.target.closest('.modal').classList.remove('show');
            });
        });

        // Close modals on outside click
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('show');
            }
        });

        // Copy share link button
        document.getElementById('copyShareBtn')?.addEventListener('click', () => {
            this.copyShareLink();
        });
    }

    loadExample(exampleKey, testCaseIndex = 0) {
        const example = EXAMPLES[exampleKey];
        if (!example) return;

        // Store current example info
        this.currentExample = exampleKey;
        this.currentTestCaseIndex = testCaseIndex;

        // Load policy
        this.policyEditor.setValue(JSON.stringify(example.policy, null, 2));
        
        // Load context - support both old format and new testCases format
        let context;
        if (example.testCases && example.testCases.length > 0) {
            context = example.testCases[testCaseIndex].context;
            this.updateTestCaseSelector(example.testCases, testCaseIndex);
        } else {
            context = example.context;
            this.hideTestCaseSelector();
        }
        
        this.contextEditor.setValue(JSON.stringify(context, null, 2));

        const caseName = example.testCases ? ` - ${example.testCases[testCaseIndex].name}` : '';
        this.updateStatus(`Loaded example: ${exampleKey}${caseName}`, 'success');
        
        // Clear any previous compilation
        this.compiledProgram = null;
        this.assemblyListing = null;
        this.clearRvmView();
        this.disableDebugControls();
    }

    updateTestCaseSelector(testCases, currentIndex) {
        let selector = document.getElementById('testCaseSelector');
        if (!selector) {
            // Create selector if it doesn't exist - place it in nav-right after example selector
            const navRight = document.querySelector('.nav-right');
            const exampleSelector = document.getElementById('exampleSelector');
            const selectorElement = document.createElement('select');
            selectorElement.id = 'testCaseSelector';
            selectorElement.className = 'nav-button';
            selectorElement.style.cssText = 'max-width: 300px; display: none;';
            
            // Insert after example selector
            exampleSelector.parentNode.insertBefore(selectorElement, exampleSelector.nextSibling);
            selector = selectorElement;
            
            selector.addEventListener('change', (e) => {
                this.loadExample(this.currentExample, parseInt(e.target.value));
            });
        }
        
        // Populate options
        selector.innerHTML = testCases.map((tc, idx) => 
            `<option value="${idx}" ${idx === currentIndex ? 'selected' : ''}>${tc.name}</option>`
        ).join('');
        
        selector.style.display = 'inline-block';
    }

    hideTestCaseSelector() {
        const selector = document.getElementById('testCaseSelector');
        if (selector) {
            selector.style.display = 'none';
        }
    }

    validatePolicy() {
        try {
            const policyText = this.policyEditor.getValue();
            const policy = JSON.parse(policyText);
            
            // Basic validation
            if (!policy.version) {
                throw new Error("Missing 'version' field");
            }
            if (!policy.roleDefinitions || !Array.isArray(policy.roleDefinitions)) {
                throw new Error("Missing or invalid 'roleDefinitions'");
            }
            if (!policy.roleAssignments || !Array.isArray(policy.roleAssignments)) {
                throw new Error("Missing or invalid 'roleAssignments'");
            }

            this.updatePolicyStatus('✓ Policy is valid', 'success');
            this.updateStatus('Policy validation passed', 'success');
        } catch (error) {
            this.updatePolicyStatus(`✗ Invalid: ${error.message}`, 'error');
            this.updateStatus(`Validation failed: ${error.message}`, 'error');
        }
    }

    compilePolicy() {
        try {
            const policyText = this.policyEditor.getValue();
            const contextText = this.contextEditor.getValue();
            
            if (!this.wasmModule) {
                this.updateStatus('WASM module not loaded. Cannot compile.', 'error');
                return;
            }

            this.updateStatus('Compiling policy to RVM bytecode...', 'warning');

            // Validate JSON first
            let policyObj, contextObj;
            try {
                policyObj = JSON.parse(policyText);
            } catch (jsonError) {
                throw new Error(`Invalid policy JSON: ${jsonError.message}`);
            }

            try {
                contextObj = JSON.parse(contextText);
            } catch (jsonError) {
                throw new Error(`Invalid context JSON: ${jsonError.message}`);
            }

            // Use WASM module to compile - it needs both policy and context
            console.log('Calling compileRbacToRvmProgram with policy and context...');
            console.log('WASM module:', this.wasmModule);
            console.log('Available methods:', Object.keys(this.wasmModule));
            
            const rvmProgram = this.wasmModule.compileRbacToRvmProgram(policyText, contextText);
            console.log('RvmProgram result:', rvmProgram);
            console.log('RvmProgram type:', typeof rvmProgram);
            console.log('RvmProgram methods:', rvmProgram ? Object.getOwnPropertyNames(Object.getPrototypeOf(rvmProgram)) : 'null');
            
            if (!rvmProgram) {
                throw new Error('Compilation returned empty result');
            }

            // Get both JSON and assembly listing
            console.log('Calling toJson() and toAssemblyListing()...');
            let programJson, assemblyListing;
            try {
                programJson = rvmProgram.toJson();
                console.log('toJson() returned, length:', programJson ? programJson.length : 'null');
                
                assemblyListing = rvmProgram.toAssemblyListing();
                console.log('toAssemblyListing() returned, length:', assemblyListing ? assemblyListing.length : 'null');
                console.log('Assembly listing preview:', assemblyListing ? assemblyListing.substring(0, 200) : 'null');
            } catch (toJsonError) {
                console.error('toJson() error:', toJsonError);
                throw new Error(`Failed to serialize RVM program: ${toJsonError}`);
            }
            
            if (!programJson) {
                throw new Error('toJson() returned undefined or empty result');
            }
            
            this.compiledProgram = JSON.parse(programJson);
            this.assemblyListing = assemblyListing;
            
            console.log('Parsed compiledProgram:', this.compiledProgram);
            console.log('compiledProgram.instructions exists:', !!this.compiledProgram.instructions);
            console.log('compiledProgram.instructions length:', this.compiledProgram.instructions ? this.compiledProgram.instructions.length : 'N/A');
            console.log('assemblyListing stored:', !!this.assemblyListing);

            if (!this.compiledProgram || !this.compiledProgram.instructions) {
                throw new Error('Compiled program is missing instructions array');
            }

            console.log('About to call displayRvmInstructions...');
            this.displayRvmInstructions(this.compiledProgram);
            console.log('displayRvmInstructions completed');
            this.updatePolicyStatus('✓ Compiled successfully', 'success');
            this.updateStatus('Policy compiled to RVM bytecode', 'success');
            this.enableDebugControls();
        } catch (error) {
            console.error('Compilation error:', error);
            this.updatePolicyStatus(`✗ Compilation failed: ${error.message}`, 'error');
            this.updateStatus(`Compilation failed: ${error.message}`, 'error');
            this.clearRvmView();
            this.disableDebugControls();
        }
    }

    evaluatePolicy() {
        try {
            const policyText = this.policyEditor.getValue();
            const contextText = this.contextEditor.getValue();

            if (!this.wasmModule) {
                this.updateStatus('WASM module not loaded. Cannot evaluate.', 'error');
                return;
            }

            this.updateStatus('Evaluating policy...', 'warning');

            console.log('Evaluating with policy:', policyText.substring(0, 200));
            console.log('Evaluating with context:', contextText.substring(0, 200));

            const startTime = performance.now();
            const result = this.wasmModule.evaluateRbacPolicy(policyText, contextText);
            const endTime = performance.now();
            const executionTime = (endTime - startTime).toFixed(2);

            console.log('evaluateRbacPolicy returned:', result);
            console.log('result type:', typeof result);

            // evaluateRbacPolicy returns a boolean, not JSON
            const evaluationResult = {
                allow: result
            };
            
            console.log('evaluationResult:', evaluationResult);
            
            this.displayEvaluationResults(evaluationResult, executionTime);
            this.updateStatus(`Evaluation completed in ${executionTime}ms`, 'success');
            
            const execTimeElement = document.getElementById('executionTime');
            if (execTimeElement) {
                execTimeElement.textContent = `Execution time: ${executionTime}ms`;
            }
        } catch (error) {
            console.error('Evaluation error:', error);
            this.updateStatus(`Evaluation failed: ${error.message}`, 'error');
            this.displayEvaluationError(error.message);
        }
    }

    displayRvmInstructions(program) {
        const view = document.getElementById('rvmInstructions');
        const stats = document.getElementById('rvmStats');

        if (!view) return;

        if (!program || !program.instructions) {
            view.innerHTML = '<p style="padding: 1rem; color: var(--text-secondary);">No instructions to display</p>';
            if (stats) stats.innerHTML = '';
            return;
        }

        // Display stats with null check
        if (stats) {
            stats.innerHTML = `
                <div class="stat-item">
                    <div class="stat-value">${program.instructions.length}</div>
                    <div class="stat-label">Instructions</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${program.literals?.length || 0}</div>
                    <div class="stat-label">Constants</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${this.countUniqueOpcodes(program.instructions)}</div>
                    <div class="stat-label">Unique Opcodes</div>
                </div>
            `;
        }

        // Display instructions using the assembly listing
        let listing = this.assemblyListing || this.formatInstructionsAsHtml(program);
        
        console.log('Displaying RVM instructions');
        console.log('assemblyListing:', this.assemblyListing ? `${this.assemblyListing.substring(0, 200)}...` : 'null');
        console.log('listing length:', listing ? listing.length : 'null');
        console.log('view element:', view);
        
        // Escape HTML if using assembly listing (plain text)
        if (this.assemblyListing) {
            listing = this.escapeHtml(listing);
            console.log('After HTML escape, listing length:', listing.length);
        }
        
        view.innerHTML = `<pre style="margin: 0; padding: 1rem; line-height: 1.6; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.875rem; white-space: pre-wrap;">${listing}</pre>`;
        console.log('view.innerHTML set, length:', view.innerHTML.length);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatInstructionsAsHtml(program) {
        let html = '';
        program.instructions.forEach((instr, idx) => {
            const opcode = Object.keys(instr)[0];
            const operands = instr[opcode];
            const operandsStr = this.formatOperands(operands);
            
            html += `<span style="color: var(--text-secondary);">${String(idx).padStart(4, ' ')}</span>  `;
            html += `<span style="color: var(--accent-green); font-weight: 600;">${opcode.padEnd(20, ' ')}</span>`;
            html += `<span style="color: var(--accent-yellow);">${operandsStr}</span>\n`;
        });
        return html;
    }

    formatOperands(operands) {
        if (operands === null || operands === undefined) return '';
        if (typeof operands === 'object') {
            return JSON.stringify(operands);
        }
        return String(operands);
    }

    countUniqueOpcodes(instructions) {
        const opcodes = new Set();
        instructions.forEach(instr => {
            opcodes.add(Object.keys(instr)[0]);
        });
        return opcodes.size;
    }

    displayEvaluationResults(result, executionTime) {
        this.switchTab('results');
        const view = document.getElementById('evaluationResults');
        if (!view) return;

        const decision = result.allow ? 'ALLOW' : 'DENY';
        const decisionClass = result.allow ? 'allow' : 'deny';

        // Check if we have an expected result from the current test case
        let expectedResult = null;
        let testPassed = null;
        if (this.currentExample && this.currentTestCaseIndex !== undefined) {
            const example = EXAMPLES[this.currentExample];
            if (example && example.testCases && example.testCases[this.currentTestCaseIndex]) {
                expectedResult = example.testCases[this.currentTestCaseIndex].expectedResult;
                testPassed = (result.allow === expectedResult);
            }
        }

        let html = `
            <div class="result-card">
                <div class="result-decision ${decisionClass}">${decision}</div>`;
        
        if (expectedResult !== null) {
            const statusIcon = testPassed ? '✓' : '✗';
            const statusClass = testPassed ? 'allow' : 'deny';
            const expectedText = expectedResult ? 'ALLOW' : 'DENY';
            html += `
                <div style="margin-top: 0.5rem; padding: 0.5rem; border-radius: 4px; background: var(--bg-secondary); font-size: 0.875rem;">
                    <span style="font-weight: 600;">Expected:</span> ${expectedText} 
                    <span style="font-weight: 700; color: var(${testPassed ? '--accent-green' : '--accent-red'});">${statusIcon} ${testPassed ? 'PASS' : 'FAIL'}</span>
                </div>`;
        }
        
        html += `
                <div class="result-details">
                    <div class="result-detail-row">
                        <span class="result-detail-label">Execution Time:</span>
                        <span class="result-detail-value">${executionTime}ms</span>
                    </div>
        `;

        if (result.matchedRole) {
            html += `
                    <div class="result-detail-row">
                        <span class="result-detail-label">Matched Role:</span>
                        <span class="result-detail-value">${result.matchedRole}</span>
                    </div>
            `;
        }

        if (result.reason) {
            html += `
                    <div class="result-detail-row">
                        <span class="result-detail-label">Reason:</span>
                        <span class="result-detail-value">${result.reason}</span>
                    </div>
            `;
        }

        html += `
                </div>
            </div>
        `;

        view.innerHTML = html;
    }

    displayEvaluationError(message) {
        this.switchTab('results');
        const view = document.getElementById('evaluationResults');
        if (!view) return;
        
        view.innerHTML = `
            <div class="result-card">
                <div class="result-decision deny">ERROR</div>
                <div class="result-details">
                    <div class="result-detail-row">
                        <span class="result-detail-label">Message:</span>
                        <span class="result-detail-value">${message}</span>
                    </div>
                </div>
            </div>
        `;
    }

    stepExecution() {
        // TODO: Implement step-by-step execution
        this.updateStatus('Step-by-step execution not yet implemented', 'warning');
    }

    runExecution() {
        // Run is essentially evaluate
        this.evaluatePolicy();
    }

    resetExecution() {
        this.executionState = {
            pc: 0,
            running: false,
            trace: [],
            vmState: {}
        };
        
        // Clear active instruction highlights
        document.querySelectorAll('.instruction.active').forEach(el => {
            el.classList.remove('active', 'executed');
        });

        this.updateStatus('Execution reset', 'success');
    }

    clearRvmView() {
        const instructions = document.getElementById('rvmInstructions');
        const stats = document.getElementById('rvmStats');
        
        if (instructions) {
            instructions.innerHTML = '<p style="padding: 1rem; color: var(--text-secondary);">Compile a policy to view RVM instructions</p>';
        }
        if (stats) {
            stats.innerHTML = '';
        }
    }

    enableDebugControls() {
        const stepBtn = document.getElementById('stepBtn');
        const runBtn = document.getElementById('runBtn');
        const resetBtn = document.getElementById('resetBtn');
        
        if (stepBtn) stepBtn.disabled = false;
        if (runBtn) runBtn.disabled = false;
        if (resetBtn) resetBtn.disabled = false;
    }

    disableDebugControls() {
        const stepBtn = document.getElementById('stepBtn');
        const runBtn = document.getElementById('runBtn');
        const resetBtn = document.getElementById('resetBtn');
        
        if (stepBtn) stepBtn.disabled = true;
        if (runBtn) runBtn.disabled = true;
        if (resetBtn) resetBtn.disabled = true;
    }

    showShareModal() {
        const policy = this.policyEditor.getValue();
        const context = this.contextEditor.getValue();
        
        // Create shareable URL with base64 encoded data
        const data = btoa(JSON.stringify({ policy, context }));
        const url = `${window.location.origin}${window.location.pathname}?share=${data}`;
        
        document.getElementById('shareUrl').value = url;
        document.getElementById('shareModal').classList.add('show');
    }

    showHelpModal() {
        document.getElementById('helpModal').classList.add('show');
    }

    copyShareLink() {
        const input = document.getElementById('shareUrl');
        input.select();
        navigator.clipboard.writeText(input.value).then(() => {
            this.updateStatus('Share link copied to clipboard', 'success');
        }).catch(err => {
            this.updateStatus('Failed to copy share link', 'error');
        });
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        // Update tab contents
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `${tabName}Tab`);
        });
    }

    updateStatus(message, type = '') {
        const statusEl = document.getElementById('statusText');
        statusEl.textContent = message;
        statusEl.className = type;
    }

    updatePolicyStatus(message, type = '') {
        const statusEl = document.getElementById('policyStatus');
        statusEl.textContent = message;
        statusEl.className = `status-bar ${type}`;
    }

    loadFromUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const shareData = urlParams.get('share');
        
        if (shareData) {
            try {
                const decoded = JSON.parse(atob(shareData));
                this.policyEditor.setValue(decoded.policy);
                this.contextEditor.setValue(decoded.context);
                this.updateStatus('Loaded shared playground state', 'success');
            } catch (error) {
                console.error('Failed to load shared data:', error);
                this.updateStatus('Failed to load shared data', 'error');
            }
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.playground = new RbacPlayground();
    });
} else {
    window.playground = new RbacPlayground();
}
