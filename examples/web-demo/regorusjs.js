/* @ts-self-types="./regorusjs.d.ts" */

/**
 * WASM wrapper for a prepared analysis problem.
 *
 * Holds the translated SMT constraints and extraction plan in memory.
 * Call `smtLib2()` to get SMT-LIB2 text for an external solver,
 * or `problemJson()` to get the full problem as JSON.
 * After solving, call `interpretSolution()` with the solver result.
 */
export class AnalysisProblem {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(AnalysisProblem.prototype);
        obj.__wbg_ptr = ptr;
        AnalysisProblemFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AnalysisProblemFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_analysisproblem_free(ptr, 0);
    }
    /**
     * Interpret a solver result and produce an analysis result.
     *
     * `solution_json` must be a JSON-serialized `SmtCheckResult` from
     * `regorus-smt`.  Returns a JSON object with `satisfiable`,
     * `input`, `warnings`, etc.
     * @param {string} solution_json
     * @returns {string}
     */
    interpretSolution(solution_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(solution_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.analysisproblem_interpretSolution(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Get the full problem as a JSON string.
     *
     * The JSON conforms to the `SmtProblem` schema from `regorus-smt`.
     * Use this for fine-grained control over solver interaction.
     * @returns {string}
     */
    problemJson() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.analysisproblem_problemJson(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get the SMT-LIB2 text representation of this problem.
     *
     * Send this to an external SMT solver (e.g., Z3 WASM).
     * @returns {string}
     */
    smtLib2() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.analysisproblem_smtLib2(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get any warnings produced during translation.
     * @returns {string[]}
     */
    warnings() {
        const ret = wasm.analysisproblem_warnings(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
}
if (Symbol.dispose) AnalysisProblem.prototype[Symbol.dispose] = AnalysisProblem.prototype.free;

/**
 * WASM wrapper for [`regorus::Engine`]
 */
export class Engine {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EngineFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_engine_free(ptr, 0);
    }
    /**
     * Add policy data.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_data
     * * `data`: JSON encoded value to be used as policy data.
     * @param {string} data
     */
    addDataJson(data) {
        const ptr0 = passStringToWasm0(data, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.engine_addDataJson(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Add a policy
     *
     * The policy is parsed into AST.
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_policy
     *
     * * `path`: A filename to be associated with the policy.
     * * `rego`: Rego policy.
     * @param {string} path
     * @param {string} rego
     * @returns {string}
     */
    addPolicy(path, rego) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(rego, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.engine_addPolicy(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Clear gathered coverage data.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.clear_coverage_data
     */
    clearCoverageData() {
        wasm.engine_clearCoverageData(this.__wbg_ptr);
    }
    /**
     * Clear policy data.
     *
     * See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.clear_data
     */
    clearData() {
        const ret = wasm.engine_clearData(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Evaluate query.
     *
     * See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.eval_query
     * * `query`: Rego expression to be evaluate.
     * @param {string} query
     * @returns {string}
     */
    evalQuery(query) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(query, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.engine_evalQuery(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Evaluate rule(s) at given path.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.eval_rule
     *
     * * `path`: The full path to the rule(s).
     * @param {string} path
     * @returns {string}
     */
    evalRule(path) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.engine_evalRule(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Get AST of policies.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_ast_as_json
     * @returns {string}
     */
    getAstAsJson() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.engine_getAstAsJson(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get the coverage report as json.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_coverage_report
     * @returns {string}
     */
    getCoverageReport() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.engine_getCoverageReport(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get ANSI color coded coverage report.
     *
     * See https://docs.rs/regorus/latest/regorus/coverage/struct.Report.html#method.to_string_pretty
     * @returns {string}
     */
    getCoverageReportPretty() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.engine_getCoverageReportPretty(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get the list of packages defined by loaded policies.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_packages
     * @returns {string[]}
     */
    getPackages() {
        const ret = wasm.engine_getPackages(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * Get the list of policies.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_policies
     * @returns {string}
     */
    getPolicies() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.engine_getPolicies(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Construct a new Engine
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html
     */
    constructor() {
        const ret = wasm.engine_new();
        this.__wbg_ptr = ret >>> 0;
        EngineFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Enable/disable policy coverage.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_enable_coverage
     * * `b`: Whether to enable gathering coverage or not.
     * @param {boolean} enable
     */
    setEnableCoverage(enable) {
        wasm.engine_setEnableCoverage(this.__wbg_ptr, enable);
    }
    /**
     * Gather output from print statements instead of emiting to stderr.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_gather_prints
     * * `b`: Whether to enable gathering prints or not.
     * @param {boolean} b
     */
    setGatherPrints(b) {
        wasm.engine_setGatherPrints(this.__wbg_ptr, b);
    }
    /**
     * Set input.
     *
     * See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_input
     * * `input`: JSON encoded value to be used as input to query.
     * @param {string} input
     */
    setInputJson(input) {
        const ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.engine_setInputJson(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Turn on rego v0.
     *
     * Regorus defaults to rego v1.
     *
     * * `enable`: Whether to enable or disable rego v0.
     * @param {boolean} enable
     */
    setRegoV0(enable) {
        wasm.engine_setRegoV0(this.__wbg_ptr, enable);
    }
    /**
     * Take the gathered output of print statements.
     *
     * See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.take_prints
     * @returns {string[]}
     */
    takePrints() {
        const ret = wasm.engine_takePrints(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
}
if (Symbol.dispose) Engine.prototype[Symbol.dispose] = Engine.prototype.free;

export class Program {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Program.prototype);
        obj.__wbg_ptr = ptr;
        ProgramFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ProgramFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_program_free(ptr, 0);
    }
    /**
     * Compile a full Azure Policy definition JSON object into an RVM program.
     *
     * `policy_definition_json` can be wrapped (`{ "properties": ... }`) or
     * unwrapped; parameter defaults are included in the compiled program.
     * `alias_map_json` is an optional JSON object mapping lowercase FQ aliases
     * to short names, typically produced from `AliasRegistry::alias_map()`.
     * @param {string} policy_definition_json
     * @param {string | null} [alias_map_json]
     * @returns {Program}
     */
    static compileAzurePolicyDefinition(policy_definition_json, alias_map_json) {
        const ptr0 = passStringToWasm0(policy_definition_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(alias_map_json) ? 0 : passStringToWasm0(alias_map_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.program_compileAzurePolicyDefinition(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Program.__wrap(ret[0]);
    }
    /**
     * Compile an Azure Policy rule JSON object into an RVM program.
     *
     * `policy_rule_json` must be the JSON for a `policyRule` object.
     * `alias_map_json` is an optional JSON object mapping lowercase FQ aliases
     * to short names, typically produced from `AliasRegistry::alias_map()`.
     * @param {string} policy_rule_json
     * @param {string | null} [alias_map_json]
     * @returns {Program}
     */
    static compileAzurePolicyRule(policy_rule_json, alias_map_json) {
        const ptr0 = passStringToWasm0(policy_rule_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(alias_map_json) ? 0 : passStringToWasm0(alias_map_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.program_compileAzurePolicyRule(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Program.__wrap(ret[0]);
    }
    /**
     * Compile a Cedar expression into an RVM program.
     * @param {string} expr
     * @returns {Program}
     */
    static compileCedarExpression(expr) {
        const ptr0 = passStringToWasm0(expr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.program_compileCedarExpression(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Program.__wrap(ret[0]);
    }
    /**
     * Compile Cedar policies into an RVM program.
     * @param {string} policies_json
     * @returns {Program}
     */
    static compileCedarPolicies(policies_json) {
        const ptr0 = passStringToWasm0(policies_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.program_compileCedarPolicies(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Program.__wrap(ret[0]);
    }
    /**
     * Compile an RVM program from modules and entry points.
     * @param {string} data_json
     * @param {string} modules_json
     * @param {string} entry_points_json
     * @returns {Program}
     */
    static compileFromModules(data_json, modules_json, entry_points_json) {
        const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(modules_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(entry_points_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.program_compileFromModules(ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return Program.__wrap(ret[0]);
    }
    /**
     * Deserialize an RVM program from binary format.
     * @param {Uint8Array} data
     * @returns {ProgramDeserializationResult}
     */
    static deserializeBinary(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.program_deserializeBinary(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ProgramDeserializationResult.__wrap(ret[0]);
    }
    /**
     * Generate a readable assembly listing.
     * @returns {string}
     */
    generateListing() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.program_generateListing(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Generate a tabular assembly listing.
     * @returns {string}
     */
    generateTabularListing() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.program_generateTabularListing(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Whether this compiled program contains any HostAwait instruction.
     *
     * Clients can use this to decide whether to run the VM in suspendable mode.
     * @returns {boolean}
     */
    get hasHostAwait() {
        const ret = wasm.program_hasHostAwait(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Serialize a program to binary format.
     * @returns {Uint8Array}
     */
    serializeBinary() {
        const ret = wasm.program_serializeBinary(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) Program.prototype[Symbol.dispose] = Program.prototype.free;

export class ProgramDeserializationResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ProgramDeserializationResult.prototype);
        obj.__wbg_ptr = ptr;
        ProgramDeserializationResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ProgramDeserializationResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_programdeserializationresult_free(ptr, 0);
    }
    /**
     * Whether the program was partially deserialized.
     * @returns {boolean}
     */
    get isPartial() {
        const ret = wasm.programdeserializationresult_isPartial(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Get the deserialized program.
     * @returns {Program}
     */
    program() {
        const ret = wasm.programdeserializationresult_program(this.__wbg_ptr);
        return Program.__wrap(ret);
    }
}
if (Symbol.dispose) ProgramDeserializationResult.prototype[Symbol.dispose] = ProgramDeserializationResult.prototype.free;

export class Rvm {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RvmFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_rvm_free(ptr, 0);
    }
    /**
     * Execute the program and return the JSON result.
     * @returns {string}
     */
    execute() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.rvm_execute(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Execute an entry point by name and return the JSON result.
     * @param {string} entry_point
     * @returns {string}
     */
    executeEntryPoint(entry_point) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.rvm_executeEntryPoint(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Get the execution state as a string.
     * @returns {string}
     */
    getExecutionState() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.rvm_getExecutionState(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Load a program into the VM.
     * @param {Program} program
     */
    loadProgram(program) {
        _assertClass(program, Program);
        wasm.rvm_loadProgram(this.__wbg_ptr, program.__wbg_ptr);
    }
    constructor() {
        const ret = wasm.rvm_new();
        this.__wbg_ptr = ret >>> 0;
        RvmFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Resume execution with an optional JSON value.
     * @param {string | null} [resume_json]
     * @returns {string}
     */
    resume(resume_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            var ptr0 = isLikeNone(resume_json) ? 0 : passStringToWasm0(resume_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            const ret = wasm.rvm_resume(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Set VM data from JSON.
     * @param {string} data_json
     */
    setDataJson(data_json) {
        const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.rvm_setDataJson(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Set execution mode (0 = run-to-completion, 1 = suspendable).
     * @param {number} mode
     */
    setExecutionMode(mode) {
        const ret = wasm.rvm_setExecutionMode(this.__wbg_ptr, mode);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Set VM input from JSON.
     * @param {string} input_json
     */
    setInputJson(input_json) {
        const ptr0 = passStringToWasm0(input_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.rvm_setInputJson(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) Rvm.prototype[Symbol.dispose] = Rvm.prototype.free;

/**
 * WASM wrapper for iterative test-suite generation.
 *
 * Usage from JS:
 * ```js
 * const suite = wasm.prepareTestSuite(program, data, output, ep, config, 10);
 * while (true) {
 *     const problem = suite.nextProblem();
 *     if (!problem) break;
 *     const solution = await solveWithZ3(problem.smtLib2());
 *     suite.recordSolution(solution);
 * }
 * const result = suite.getResult();
 * ```
 */
export class TestSuitePlan {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(TestSuitePlan.prototype);
        obj.__wbg_ptr = ptr;
        TestSuitePlanFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        TestSuitePlanFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_testsuiteplan_free(ptr, 0);
    }
    /**
     * Get the final test-suite result as JSON.
     *
     * Returns `{ test_cases, coverable_lines, covered_lines,
     *   condition_goals, condition_goals_covered, warnings }`.
     * @returns {string}
     */
    getResult() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.testsuiteplan_getResult(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get the next SMT problem to solve, or `undefined` if all lines
     * have been covered (or `max_tests` reached).
     * @returns {AnalysisProblem | undefined}
     */
    nextProblem() {
        const ret = wasm.testsuiteplan_nextProblem(this.__wbg_ptr);
        return ret === 0 ? undefined : AnalysisProblem.__wrap(ret);
    }
    /**
     * Record a solver result for the current target line.
     *
     * `solution_json` is a JSON `SmtCheckResult`.
     * Returns JSON: `{ "satisfiable": bool, "input": string|null,
     *   "covered_lines": [[file, line], ...],
     *   "condition_coverage": [["file:line", bool], ...] }` on SAT, or
     * `{ "satisfiable": false }` on UNSAT/Unknown.
     * @param {string} solution_json
     * @returns {string}
     */
    recordSolution(solution_json) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(solution_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.testsuiteplan_recordSolution(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
}
if (Symbol.dispose) TestSuitePlan.prototype[Symbol.dispose] = TestSuitePlan.prototype.free;

/**
 * Prepare an analysis problem for a given goal.
 *
 * `goal` is one of:
 *   - `"expected"` — entry point must produce `desired_output_json` (required).
 *   - `"non-default"` — entry point must produce any non-default value.
 *   - `"satisfiable"` — entry point must produce any defined value.
 *   - `"cover"` — cover specific lines (via `cover_lines`/`avoid_lines` in config).
 *   - `"output-and-cover"` — both expected output AND line coverage.
 *
 * * `program` — Compiled RVM program.
 * * `data_json` — JSON-encoded policy data.
 * * `entry_point` — Entry point name.
 * * `goal` — Goal type string (see above).
 * * `desired_output_json` — Required for `"expected"` and `"output-and-cover"`.
 * * `config_json` — Optional JSON `AnalysisConfig`.
 * @param {Program} program
 * @param {string} data_json
 * @param {string} entry_point
 * @param {string} goal
 * @param {string | null} [desired_output_json]
 * @param {string | null} [config_json]
 * @returns {AnalysisProblem}
 */
export function prepareForGoal(program, data_json, entry_point, goal, desired_output_json, config_json) {
    _assertClass(program, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(goal, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(desired_output_json) ? 0 : passStringToWasm0(desired_output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.prepareForGoal(program.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AnalysisProblem.__wrap(ret[0]);
}

/**
 * Prepare a generate-input analysis problem.
 *
 * Translates the policy to SMT constraints targeting the given output.
 * Returns an `AnalysisProblem` that can be sent to an external solver.
 *
 * * `program` — Compiled RVM program.
 * * `data_json` — JSON-encoded policy data (or `"{}"`).
 * * `desired_output_json` — The value the entry point should produce (e.g., `"true"`).
 * * `entry_point` — Entry point name (e.g., `"data.test.allow"`).
 * * `config_json` — Optional JSON `AnalysisConfig` (uses defaults if omitted).
 * @param {Program} program
 * @param {string} data_json
 * @param {string} desired_output_json
 * @param {string} entry_point
 * @param {string | null} [config_json]
 * @returns {AnalysisProblem}
 */
export function prepareGenerateInput(program, data_json, desired_output_json, entry_point, config_json) {
    _assertClass(program, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(desired_output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.prepareGenerateInput(program.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AnalysisProblem.__wrap(ret[0]);
}

/**
 * Prepare a satisfiability-check analysis problem.
 *
 * Checks whether any input can make the entry point produce a
 * non-undefined result.
 *
 * * `program` — Compiled RVM program.
 * * `data_json` — JSON-encoded policy data.
 * * `entry_point` — Entry point name.
 * * `config_json` — Optional JSON `AnalysisConfig`.
 * @param {Program} program
 * @param {string} data_json
 * @param {string} entry_point
 * @param {string | null} [config_json]
 * @returns {AnalysisProblem}
 */
export function prepareIsSatisfiable(program, data_json, entry_point, config_json) {
    _assertClass(program, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.prepareIsSatisfiable(program.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AnalysisProblem.__wrap(ret[0]);
}

/**
 * Prepare a policy-diff analysis problem.
 *
 * Finds an input where two policies disagree.
 *
 * * `program1`, `program2` — The two compiled RVM programs to compare.
 * * `data_json` — JSON-encoded policy data (shared).
 * * `entry_point` — Entry point name (must exist in both programs).
 * * `desired_output_json` — Optional desired output; defaults to `true`.
 * * `config_json` — Optional JSON `AnalysisConfig`.
 * @param {Program} program1
 * @param {Program} program2
 * @param {string} data_json
 * @param {string} entry_point
 * @param {string | null} [desired_output_json]
 * @param {string | null} [config_json]
 * @returns {AnalysisProblem}
 */
export function preparePolicyDiff(program1, program2, data_json, entry_point, desired_output_json, config_json) {
    _assertClass(program1, Program);
    _assertClass(program2, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(desired_output_json) ? 0 : passStringToWasm0(desired_output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.preparePolicyDiff(program1.__wbg_ptr, program2.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AnalysisProblem.__wrap(ret[0]);
}

/**
 * Prepare a policy-subsumption check.
 *
 * Checks: for all inputs, if `old_program` produces `desired_output`
 * then `new_program` also produces `desired_output`.
 *
 * When the result is SAT, a counterexample was found and subsumption
 * does NOT hold.  When UNSAT, subsumption holds.
 *
 * * `old_program`, `new_program` — The two compiled RVM programs.
 * * `data_json` — JSON-encoded policy data (shared).
 * * `entry_point` — Entry point name (must exist in both programs).
 * * `desired_output_json` — The desired output value.
 * * `config_json` — Optional JSON `AnalysisConfig`.
 * @param {Program} old_program
 * @param {Program} new_program
 * @param {string} data_json
 * @param {string} entry_point
 * @param {string} desired_output_json
 * @param {string | null} [config_json]
 * @returns {AnalysisProblem}
 */
export function preparePolicySubsumes(old_program, new_program, data_json, entry_point, desired_output_json, config_json) {
    _assertClass(old_program, Program);
    _assertClass(new_program, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(desired_output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.preparePolicySubsumes(old_program.__wbg_ptr, new_program.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return AnalysisProblem.__wrap(ret[0]);
}

/**
 * Prepare an iterative test-suite generator.
 *
 * * `program` — Compiled RVM program.
 * * `data_json` — JSON-encoded policy data.
 * * `desired_output_json` — Optional output constraint (e.g., `"false"`).
 * * `entry_point` — Entry point name.
 * * `config_json` — Optional JSON `AnalysisConfig`.
 * * `max_tests` — Maximum number of test cases to generate.
 * * `condition_coverage` — Whether to include condition-coverage (Phase 2).
 * @param {Program} program
 * @param {string} data_json
 * @param {string | null | undefined} desired_output_json
 * @param {string} entry_point
 * @param {string | null | undefined} config_json
 * @param {number} max_tests
 * @param {boolean} condition_coverage
 * @returns {TestSuitePlan}
 */
export function prepareTestSuite(program, data_json, desired_output_json, entry_point, config_json, max_tests, condition_coverage) {
    _assertClass(program, Program);
    const ptr0 = passStringToWasm0(data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(desired_output_json) ? 0 : passStringToWasm0(desired_output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(entry_point, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(config_json) ? 0 : passStringToWasm0(config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    const ret = wasm.prepareTestSuite(program.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, max_tests, condition_coverage);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return TestSuitePlan.__wrap(ret[0]);
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_1c61fac11405ffdc: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_9c5c1b115e142bb8: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getTime_1e3cd1391c5c3995: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_getTimezoneOffset_81776d10a4ec18a8: function(arg0) {
            const ret = arg0.getTimezoneOffset();
            return ret;
        },
        __wbg_new_0_73afc35eb544e539: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_245cd5c49157e602: function(arg0) {
            const ret = new Date(arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./regorusjs_bg.js": import0,
    };
}

const AnalysisProblemFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_analysisproblem_free(ptr >>> 0, 1));
const EngineFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_engine_free(ptr >>> 0, 1));
const ProgramFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_program_free(ptr >>> 0, 1));
const ProgramDeserializationResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_programdeserializationresult_free(ptr >>> 0, 1));
const RvmFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_rvm_free(ptr >>> 0, 1));
const TestSuitePlanFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_testsuiteplan_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('regorusjs_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
