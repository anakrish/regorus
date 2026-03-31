// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable
namespace Regorus
{
    /// <summary>
    /// Provides static methods for compiling Azure Policy JSON definitions into
    /// RVM programs that can be executed via <see cref="Rvm"/>.
    /// </summary>
    public static unsafe class AzurePolicyCompiler
    {
        /// <summary>
        /// Compile an Azure Policy definition JSON into an RVM <see cref="Program"/>.
        /// </summary>
        /// <param name="policyJson">The Azure Policy definition JSON string</param>
        /// <param name="aliasRegistry">
        /// Optional alias registry for alias resolution. Pass null to compile without alias expansion.
        /// </param>
        /// <returns>A compiled <see cref="Program"/> ready for execution in an <see cref="Rvm"/>.</returns>
        public static Program CompileDefinition(string policyJson, AliasRegistry? aliasRegistry = null)
        {
            if (policyJson is null)
            {
                throw new ArgumentNullException(nameof(policyJson));
            }

            if (aliasRegistry is null)
            {
                return Utf8Marshaller.WithUtf8(policyJson, policyPtr =>
                {
                    var result = API.regorus_compile_azure_policy_definition(
                        null, (byte*)policyPtr);
                    return GetProgramResult(result);
                });
            }

            return aliasRegistry.UseHandleForInterop(regPtr =>
            {
                return Utf8Marshaller.WithUtf8(policyJson, policyPtr =>
                {
                    var result = API.regorus_compile_azure_policy_definition(
                        (RegorusAliasRegistry*)regPtr, (byte*)policyPtr);
                    return GetProgramResult(result);
                });
            });
        }

        private static Program GetProgramResult(RegorusResult result)
        {
            try
            {
                if (result.status != RegorusStatus.Ok)
                {
                    var message = Utf8Marshaller.FromUtf8(result.error_message);
                    throw result.status.CreateException(message);
                }

                if (result.data_type != RegorusDataType.Pointer || result.pointer_value == null)
                {
                    throw new Exception("Expected program pointer but got different data type");
                }

                var handle = RegorusProgramHandle.FromPointer((IntPtr)result.pointer_value);
                return new Program(handle);
            }
            finally
            {
                API.regorus_result_drop(result);
            }
        }
    }
}
