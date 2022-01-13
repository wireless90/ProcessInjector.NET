using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace ObjectCloner.Internal
{
	internal static class TypeHelper
	{
		private static readonly ConcurrentDictionary<Type, bool> _canSkipDeepCloneMap = new ConcurrentDictionary<Type, bool>();

		public static bool CanSkipDeepClone(Type type)
		{
			return _canSkipDeepCloneMap.GetOrAdd(type, (Type t) => t.IsPrimitive || t == typeof(string) || t == typeof(object));
		}

		public static IEnumerable<FieldInfo> GetAllFieldsDeep(this Type type)
		{
			if (type == typeof(object))
			{
				return Enumerable.Empty<FieldInfo>();
			}
			return type.GetFields(BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Concat(type.BaseType.GetAllFieldsDeep());
		}
	}
}
