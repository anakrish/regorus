// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
    /// <summary>
    /// Managed wrapper over regorus::lazy::LazyContext.
    /// </summary>
    public sealed unsafe class LazyContext : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public LazyContext()
        {
            var result = Internal.API.regorus_lazy_context_create();
            var handle = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerLazyContext);
            _handle = handle;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed || _handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(LazyContext));
            }
        }

        public void Insert(string key, ulong value)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_u64((void*)_handle, keyPtr, value));
            }
        }

        public void Insert(string key, long value)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_i64((void*)_handle, keyPtr, value));
            }
        }

        public void Insert(string key, string value)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            var valueBytes = NativeUtf8.GetNullTerminatedBytes(value);
            fixed (byte* keyPtr = keyBytes)
            fixed (byte* valuePtr = valueBytes)
            {
                NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_string((void*)_handle, keyPtr, valuePtr));
            }
        }

        public void Insert(string key, bool value)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_bool((void*)_handle, keyPtr, value ? (byte)1 : (byte)0));
            }
        }

        public void Insert(string key, byte[] bytes)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (bytes is null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                if (bytes.Length == 0)
                {
                    NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_bytes((void*)_handle, keyPtr, null, UIntPtr.Zero));
                }
                else
                {
                    fixed (byte* bytesPtr = bytes)
                    {
                        NativeResult.EnsureSuccess(Internal.API.regorus_lazy_context_insert_bytes((void*)_handle, keyPtr, bytesPtr, new UIntPtr((ulong)bytes.LongLength)));
                    }
                }
            }
        }

        public ulong GetUInt64(string key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            ThrowIfDisposed();
            var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
            fixed (byte* keyPtr = keyBytes)
            {
                return NativeResult.GetUInt64AndDrop(Internal.API.regorus_lazy_context_get_u64((void*)_handle, keyPtr));
            }
        }

        internal IntPtr Detach()
        {
            ThrowIfDisposed();
            _disposed = true;
            var handle = _handle;
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
            return handle;
        }

        private void DisposeHandle()
        {
            if (_handle != IntPtr.Zero)
            {
                Internal.API.regorus_lazy_context_drop((void*)_handle);
                _handle = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            DisposeHandle();
            GC.SuppressFinalize(this);
        }

        ~LazyContext()
        {
            DisposeHandle();
        }
    }
}
