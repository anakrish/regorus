// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Regorus.Internal;

#nullable enable

namespace Regorus
{
	/// <summary>
	/// Managed wrapper for the native regorus::Value type.
	/// Instances own the underlying native value and must be disposed when no longer needed.
	/// </summary>
	public sealed unsafe class Value : IDisposable
	{
		private IntPtr _handle;
		private bool _disposed;

		private Value(IntPtr handle)
		{
			if (handle == IntPtr.Zero)
			{
				throw new ArgumentNullException(nameof(handle));
			}

			_handle = handle;
		}

		internal static Value FromHandle(IntPtr handle) => new Value(handle);

		private void ThrowIfDisposed()
		{
			if (_disposed || _handle == IntPtr.Zero)
			{
				throw new ObjectDisposedException(nameof(Value));
			}
		}

		private IntPtr MoveHandle()
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
				Internal.API.regorus_value_drop((void*)_handle);
				_handle = IntPtr.Zero;
			}
		}

		public static Value Null()
		{
			var result = Internal.API.regorus_value_create_null();
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Undefined()
		{
			var result = Internal.API.regorus_value_create_undefined();
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Bool(bool value)
		{
			var result = Internal.API.regorus_value_create_bool(value);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Int(long value)
		{
			var result = Internal.API.regorus_value_create_int(value);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Float(double value)
		{
			var result = Internal.API.regorus_value_create_float(value);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value String(string value)
		{
			if (value is null)
			{
				throw new ArgumentNullException(nameof(value));
			}

			var bytes = NativeUtf8.GetNullTerminatedBytes(value);
			fixed (byte* ptr = bytes)
			{
				var result = Internal.API.regorus_value_create_string(ptr);
				var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
				return new Value(pointer);
			}
		}

		public static Value Array()
		{
			var result = Internal.API.regorus_value_create_array();
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Object()
		{
			var result = Internal.API.regorus_value_create_object();
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value Set()
		{
			var result = Internal.API.regorus_value_create_set();
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public static Value FromJson(string json)
		{
			if (json is null)
			{
				throw new ArgumentNullException(nameof(json));
			}

			var bytes = NativeUtf8.GetNullTerminatedBytes(json);
			fixed (byte* ptr = bytes)
			{
				var result = Internal.API.regorus_value_from_json(ptr);
				var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
				return new Value(pointer);
			}
		}

		public Value Clone()
		{
			ThrowIfDisposed();
			var result = Internal.API.regorus_value_clone((void*)_handle);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public string ToJson()
		{
			ThrowIfDisposed();
			var result = Internal.API.regorus_value_to_json((void*)_handle);
			return NativeResult.GetStringAndDrop(result) ?? string.Empty;
		}

		public bool IsNull
		{
			get
			{
				ThrowIfDisposed();
				return NativeResult.GetBoolAndDrop(Internal.API.regorus_value_is_null((void*)_handle));
			}
		}

		public bool IsObject
		{
			get
			{
				ThrowIfDisposed();
				return NativeResult.GetBoolAndDrop(Internal.API.regorus_value_is_object((void*)_handle));
			}
		}

		public bool IsLazyObject
		{
			get
			{
				ThrowIfDisposed();
				return NativeResult.GetBoolAndDrop(Internal.API.regorus_value_is_lazy_object((void*)_handle));
			}
		}

		public bool IsString
		{
			get
			{
				ThrowIfDisposed();
				return NativeResult.GetBoolAndDrop(Internal.API.regorus_value_is_string((void*)_handle));
			}
		}

		public bool AsBool()
		{
			ThrowIfDisposed();
			return NativeResult.GetBoolAndDrop(Internal.API.regorus_value_as_bool((void*)_handle));
		}

		public long AsInt64()
		{
			ThrowIfDisposed();
			return NativeResult.GetInt64AndDrop(Internal.API.regorus_value_as_i64((void*)_handle));
		}

		public string AsString()
		{
			ThrowIfDisposed();
			return NativeResult.GetStringAndDrop(Internal.API.regorus_value_as_string((void*)_handle)) ?? string.Empty;
		}

		public long ArrayLength()
		{
			ThrowIfDisposed();
			return NativeResult.GetInt64AndDrop(Internal.API.regorus_value_array_len((void*)_handle));
		}

		public Value ArrayGet(long index)
		{
			ThrowIfDisposed();
			var result = Internal.API.regorus_value_array_get((void*)_handle, index);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
		}

		public void ObjectInsert(string key, Value value)
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
			var valueHandle = value.MoveHandle();
			fixed (byte* keyPtr = keyBytes)
			{
				NativeResult.EnsureSuccess(Internal.API.regorus_value_object_insert((void*)_handle, keyPtr, (void*)valueHandle));
			}
		}

		public Value ObjectGet(string key)
		{
			if (key is null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			ThrowIfDisposed();
			var keyBytes = NativeUtf8.GetNullTerminatedBytes(key);
			fixed (byte* keyPtr = keyBytes)
			{
				var result = Internal.API.regorus_value_object_get((void*)_handle, keyPtr);
				var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
				return new Value(pointer);
			}
		}

		public IntPtr Detach()
		{
			return MoveHandle();
		}

		public static Value FromLazyObject(LazyObject lazyObject)
		{
			if (lazyObject is null)
			{
				throw new ArgumentNullException(nameof(lazyObject));
			}

			var lazyHandle = lazyObject.Detach();
			var result = Internal.API.regorus_value_from_lazy_object((void*)lazyHandle);
			var pointer = NativeResult.GetPointerAndDrop(result, RegorusPointerType.PointerValue);
			return new Value(pointer);
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

		~Value()
		{
			DisposeHandle();
		}
	}
}
