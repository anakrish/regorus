// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Text;
using Regorus.Internal;


#nullable enable
namespace Regorus
{
    /// <summary>
    /// C# Wrapper for the Regorus engine.
    /// This class is not thread-safe. For multithreaded use, prefer cloning after adding policies and data to an instance.
    /// Cloning is cheap and involves only incrementing reference counts for shared immutable objects like parsed policies,
    /// data etc. Mutable state is deep copied as needed.
    /// </summary>
    public unsafe sealed class Engine : System.IDisposable
    {
        private Regorus.Internal.RegorusEngine* E;
        // Detect redundant Dispose() calls in a thread-safe manner.
        // _isDisposed == 0 means Dispose(bool) has not been called yet.
        // _isDisposed == 1 means Dispose(bool) has been already called.
        private int isDisposed;

        public Engine()
        {
            E = Regorus.Internal.API.regorus_engine_new();
        }

        public void Dispose()
        {
            Dispose(disposing: true);

            // This object will be cleaned up by the Dispose method.
            // Therefore, call GC.SuppressFinalize to
            // take this object off the finalization queue
            // and prevent finalization code for this object
            // from executing a second time.
            GC.SuppressFinalize(this);
        }

        // Dispose(bool disposing) executes in two distinct scenarios.
        // If disposing equals true, the method has been called directly
        // or indirectly by a user's code. Managed and unmanaged resources
        // can be disposed.
        // If disposing equals false, the method has been called by the
        // runtime from inside the finalizer and you should not reference
        // other objects. Only unmanaged resources can be disposed.
        void Dispose(bool disposing)
        {
            // In case _isDisposed is 0, atomically set it to 1.
            // Enter the branch only if the original value is 0.
            if (System.Threading.Interlocked.CompareExchange(ref isDisposed, 1, 0) == 0)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // No managed resource to dispose.
                }

                // Call the appropriate methods to clean up
                // unmanaged resources here.
                // If disposing is false,
                // only the following code is executed.
                if (E != null)
                {
                    Regorus.Internal.API.regorus_engine_drop(E);
                    E = null;
                }

            }
        }

        // Use C# finalizer syntax for finalization code.
        // This finalizer will run only if the Dispose method
        // does not get called.
        ~Engine() => Dispose(disposing: false);

        // Helper for implementing Clone
        private Engine(Internal.RegorusEngine* engine)
        {
            this.E = engine;
        }

        public Engine Clone() => new(Internal.API.regorus_engine_clone(E));

        public void SetStrictBuiltinErrors(bool strict)
        {
            CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_strict_builtin_errors(E, strict));
        }
        public string? AddPolicy(string path, string rego)
        {
            var pathBytes = NativeUtf8.GetNullTerminatedBytes(path);
            var regoBytes = NativeUtf8.GetNullTerminatedBytes(rego);


            fixed (byte* pathPtr = pathBytes)
            {
                fixed (byte* regoPtr = regoBytes)
                {
                    return CheckAndDropResult(Regorus.Internal.API.regorus_engine_add_policy(E, pathPtr, regoPtr));
                }
            }

        }

        public void SetRegoV0(bool enable)
        {
            CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_rego_v0(E, enable));
        }

        public string? AddPolicyFromFile(string path)
        {
            var pathBytes = NativeUtf8.GetNullTerminatedBytes(path);
            fixed (byte* pathPtr = pathBytes)
            {
                return CheckAndDropResult(Regorus.Internal.API.regorus_engine_add_policy_from_file(E, pathPtr));
            }

        }

        public void AddDataJson(string data)
        {
            var dataBytes = NativeUtf8.GetNullTerminatedBytes(data);
            fixed (byte* dataPtr = dataBytes)
            {
                CheckAndDropResult(Regorus.Internal.API.regorus_engine_add_data_json(E, dataPtr));
            }

        }

        public void AddDataFromJsonFile(string path)
        {
            var pathBytes = NativeUtf8.GetNullTerminatedBytes(path);
            fixed (byte* pathPtr = pathBytes)
            {
                CheckAndDropResult(Regorus.Internal.API.regorus_engine_add_data_from_json_file(E, pathPtr));
            }

        }

        public void AddDataValue(Value value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var handle = value.Detach();
            NativeResult.EnsureSuccess(Regorus.Internal.API.regorus_engine_add_data_value(E, (void*)handle));
        }

        public void SetInputJson(string input)
        {
            var inputBytes = NativeUtf8.GetNullTerminatedBytes(input);
            fixed (byte* inputPtr = inputBytes)
            {
                CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_input_json(E, inputPtr));
            }
        }

        public void SetInputFromJsonFile(string path)
        {
            var pathBytes = NativeUtf8.GetNullTerminatedBytes(path);
            fixed (byte* pathPtr = pathBytes)
            {
                CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_input_from_json_file(E, pathPtr));
            }
        }

        public void SetInputValue(Value value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var handle = value.Detach();
            NativeResult.EnsureSuccess(Regorus.Internal.API.regorus_engine_set_input_value(E, (void*)handle));
        }

        public string? EvalQuery(string query)
        {
            var queryBytes = NativeUtf8.GetNullTerminatedBytes(query);
            fixed (byte* queryPtr = queryBytes)
            {
                return CheckAndDropResult(Regorus.Internal.API.regorus_engine_eval_query(E, queryPtr));
            }
        }

        public Value EvalQueryAsValue(string query)
        {
            var queryBytes = NativeUtf8.GetNullTerminatedBytes(query);
            fixed (byte* queryPtr = queryBytes)
            {
                var result = Regorus.Internal.API.regorus_engine_eval_query_as_value(E, queryPtr);
                var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
                return Value.FromHandle(pointer);
            }
        }

        public string? EvalRule(string rule)
        {
            var ruleBytes = NativeUtf8.GetNullTerminatedBytes(rule);
            fixed (byte* rulePtr = ruleBytes)
            {
                return CheckAndDropResult(Regorus.Internal.API.regorus_engine_eval_rule(E, rulePtr));
            }
        }

        public Value EvalRuleAsValue(string rule)
        {
            var ruleBytes = NativeUtf8.GetNullTerminatedBytes(rule);
            fixed (byte* rulePtr = ruleBytes)
            {
                var result = Regorus.Internal.API.regorus_engine_eval_rule_as_value(E, rulePtr);
                var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
                return Value.FromHandle(pointer);
            }
        }

        public void SetEnableCoverage(bool enable)
        {
            CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_enable_coverage(E, enable));
        }

        public void ClearCoverageData()
        {
            CheckAndDropResult(Regorus.Internal.API.regorus_engine_clear_coverage_data(E));
        }

        public string? GetCoverageReport()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_get_coverage_report(E));
        }

        public string? GetCoverageReportPretty()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_get_coverage_report_pretty(E));
        }

        public void SetGatherPrints(bool enable)
        {
            CheckAndDropResult(Regorus.Internal.API.regorus_engine_set_gather_prints(E, enable));
        }

        public string? TakePrints()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_take_prints(E));
        }

        public string? GetAstAsJson()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_get_ast_as_json(E));
        }

        public string? GetPolicyPackageNames()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_get_policy_package_names(E));
        }

        public string? GetPolicyParameters()
        {
            return CheckAndDropResult(Regorus.Internal.API.regorus_engine_get_policy_parameters(E));
        }

        string? CheckAndDropResult(Regorus.Internal.RegorusResult result)
        {
            return NativeResult.GetStringAndDrop(result);
        }

    }
}
