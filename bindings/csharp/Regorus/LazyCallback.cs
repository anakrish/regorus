// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
    /// <summary>
    /// Lightweight view over a native lazy context passed to callback field getters.
    /// </summary>
    public readonly struct LazyCallbackContext
    {
        private readonly IntPtr _handle;

        internal LazyCallbackContext(IntPtr handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Retrieves a 64-bit unsigned integer previously inserted into the context.
        /// </summary>
        /// <param name="key">Context key.</param>
        /// <returns>Stored unsigned integer value.</returns>
        public unsafe ulong GetUInt64(string key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Lazy context handle is not valid.");
            }

            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                return NativeResult.GetUInt64AndDrop(API.regorus_lazy_context_get_u64((void*)_handle, keyPtr));
            }
        }

        /// <summary>
        /// Retrieves a string previously stored in the context.
        /// </summary>
        /// <param name="key">Context key.</param>
        public unsafe string GetString(string key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Lazy context handle is not valid.");
            }

            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                return NativeResult.GetStringAndDrop(API.regorus_lazy_context_get_string((void*)_handle, keyPtr)) ?? string.Empty;
            }
        }
    }

    /// <summary>
    /// Delegate used to resolve lazy field values from managed code.
    /// </summary>
    /// <param name="context">Context view shared for the current lazy evaluation.</param>
    /// <param name="fieldName">Field being resolved.</param>
    /// <param name="userData">Optional user data supplied during schema registration.</param>
    /// <returns>A new <see cref="Value"/> instance representing the field value.</returns>
    public delegate Value LazyFieldGetter(LazyCallbackContext context, string fieldName, object? userData);

    /// <summary>
    /// Callback field definition linking a field name to its managed resolver.
    /// </summary>
    public sealed class LazyCallbackField
    {
        public LazyCallbackField(string name, LazyFieldGetter getter, object? userData = null)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Getter = getter ?? throw new ArgumentNullException(nameof(getter));
            UserData = userData;
        }

        public string Name { get; }

        internal LazyFieldGetter Getter { get; }

        internal object? UserData { get; }
    }
}
