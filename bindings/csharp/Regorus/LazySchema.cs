// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
    /// <summary>
    /// Helpers for registering lazy schemas with the native registry.
    /// </summary>
    public static unsafe class LazySchema
    {
        private static readonly List<GCHandle> s_callbackRegistrations = new();
        private static readonly object s_callbackSync = new();
        private static readonly API.FieldGetterCallback s_fieldGetterThunk = FieldGetterThunk;
        private static readonly IntPtr s_fieldGetterThunkPtr = Marshal.GetFunctionPointerForDelegate(s_fieldGetterThunk);

        public static void RegisterContextSchema(
            string typeName,
            IEnumerable<string>? stringFields = null,
            IEnumerable<string>? i64Fields = null,
            IEnumerable<string>? u64Fields = null,
            IEnumerable<string>? boolFields = null)
        {
            if (typeName is null)
            {
                throw new ArgumentNullException(nameof(typeName));
            }

            var typeBytes = NativeUtf8.GetNullTerminatedBytes(typeName);

            using var stringPinned = new PinnedUtf8StringArray(stringFields);
            using var i64Pinned = new PinnedUtf8StringArray(i64Fields);
            using var u64Pinned = new PinnedUtf8StringArray(u64Fields);
            using var boolPinned = new PinnedUtf8StringArray(boolFields);

            fixed (byte* typePtr = typeBytes)
            {
                NativeResult.EnsureSuccess(
                    Internal.API.regorus_register_context_schema(
                        typePtr,
                        stringPinned.Pointer,
                        stringPinned.LengthPtr,
                        i64Pinned.Pointer,
                        i64Pinned.LengthPtr,
                        u64Pinned.Pointer,
                        u64Pinned.LengthPtr,
                        boolPinned.Pointer,
                        boolPinned.LengthPtr));
            }
        }

        public static void RegisterCallbackSchema(string typeName, params LazyCallbackField[] fields)
        {
            if (typeName is null)
            {
                throw new ArgumentNullException(nameof(typeName));
            }

            if (fields is null)
            {
                throw new ArgumentNullException(nameof(fields));
            }

            if (fields.Length == 0)
            {
                throw new ArgumentException("At least one field must be provided.", nameof(fields));
            }

            var fieldNames = new string[fields.Length];
            var callbackPointers = new List<IntPtr>(fields.Length);
            var userDataPointers = new List<IntPtr>(fields.Length);
            var handles = new List<GCHandle>(fields.Length);

            for (int i = 0; i < fields.Length; i++)
            {
                var field = fields[i] ?? throw new ArgumentNullException(nameof(fields), "Field definitions cannot be null.");
                fieldNames[i] = field.Name;

                var registration = new CallbackRegistration(field);
                var handle = GCHandle.Alloc(registration, GCHandleType.Normal);
                handles.Add(handle);

                callbackPointers.Add(s_fieldGetterThunkPtr);
                userDataPointers.Add(GCHandle.ToIntPtr(handle));
            }

            var typeBytes = NativeUtf8.GetNullTerminatedBytes(typeName);

            using var namesPinned = new PinnedUtf8StringArray(fieldNames);
            using var callbacksPinned = new PinnedIntPtrArray(callbackPointers);
            using var userDataPinned = new PinnedIntPtrArray(userDataPointers);

            try
            {
                fixed (byte* typePtr = typeBytes)
                {
                    NativeResult.EnsureSuccess(
                        API.regorus_register_callback_schema(
                            typePtr,
                            namesPinned.Pointer,
                            callbacksPinned.Pointer,
                            userDataPinned.Pointer,
                            namesPinned.LengthPtr));
                }

                lock (s_callbackSync)
                {
                    s_callbackRegistrations.AddRange(handles);
                }
            }
            catch
            {
                foreach (var handle in handles)
                {
                    if (handle.IsAllocated)
                    {
                        handle.Free();
                    }
                }

                throw;
            }
        }

        private static IntPtr FieldGetterThunk(IntPtr contextPtr, IntPtr fieldNamePtr, IntPtr userDataPtr)
        {
            if (userDataPtr == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            try
            {
                var handle = GCHandle.FromIntPtr(userDataPtr);
                if (handle.Target is not CallbackRegistration registration)
                {
                    return IntPtr.Zero;
                }

                var field = registration.Field;
                var context = new LazyCallbackContext(contextPtr);
                var fieldName = NativeUtf8.PtrToString(fieldNamePtr) ?? field.Name;
                var value = field.Getter(context, fieldName, field.UserData);

                if (value is null)
                {
                    return IntPtr.Zero;
                }

                return value.Detach();
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        private sealed class CallbackRegistration
        {
            internal CallbackRegistration(LazyCallbackField field)
            {
                Field = field;
            }

            internal LazyCallbackField Field { get; }
        }
    }
}
