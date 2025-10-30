// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
    /// <summary>
    /// Managed wrapper over regorus::lazy::TypeId.
    /// </summary>
    public sealed unsafe class TypeId : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        private TypeId(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(handle));
            }

            _handle = handle;
        }

        public static TypeId Create(string name)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var bytes = NativeUtf8.GetNullTerminatedBytes(name);
            fixed (byte* ptr = bytes)
            {
                var result = Internal.API.regorus_typeid_create(ptr);
                var handle = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerTypeId);
                return new TypeId(handle);
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

        private void ThrowIfDisposed()
        {
            if (_disposed || _handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(TypeId));
            }
        }

        private void DisposeHandle()
        {
            if (_handle != IntPtr.Zero)
            {
                Internal.API.regorus_typeid_drop((void*)_handle);
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

        ~TypeId()
        {
            DisposeHandle();
        }
    }
}
