// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
    /// <summary>
    /// Managed wrapper over regorus::lazy::LazyObject.
    /// </summary>
    public sealed unsafe class LazyObject : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        private LazyObject(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                throw new ArgumentNullException(nameof(handle));
            }

            _handle = handle;
        }

        public static LazyObject Create(TypeId typeId, LazyContext context)
        {
            if (typeId is null)
            {
                throw new ArgumentNullException(nameof(typeId));
            }
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var typeHandle = typeId.Detach();
            var contextHandle = context.Detach();
            var result = Internal.API.regorus_lazy_object_create((void*)typeHandle, (void*)contextHandle);
            var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerLazyObject);
            return new LazyObject(pointer);
        }

        public Value ToValue()
        {
            if (_disposed || _handle == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(LazyObject));
            }

            var lazyHandle = Detach();
            var result = Internal.API.regorus_value_from_lazy_object((void*)lazyHandle);
            var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
            return Value.FromHandle(pointer);
        }

        internal IntPtr Detach()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(LazyObject));
            }

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
                Internal.API.regorus_lazy_object_drop((void*)_handle);
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

        ~LazyObject()
        {
            DisposeHandle();
        }
    }
}
