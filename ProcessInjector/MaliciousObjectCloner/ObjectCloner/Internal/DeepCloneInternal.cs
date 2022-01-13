using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace ObjectCloner.Internal
{
	internal static class DeepCloneInternal
	{
		private static readonly ConcurrentDictionary<Type, DeepCloner> _clonerMap = new ConcurrentDictionary<Type, DeepCloner>();

		public static DeepCloner GetDeepCloner(Type type)
		{
			return _clonerMap.GetOrAdd(type, (Type t) => TypeHelper.CanSkipDeepClone(type) ? new DeepCloner(Identity) : new DeepCloneExpressionBuilder(t).Build().Compile());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static object Identity(object input, Dictionary<object, object> _)
		{
			return input;
		}
	}
}
