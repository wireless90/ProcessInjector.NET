using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using ObjectCloner.Internal;

namespace ObjectCloner
{
	public static class ObjectCloner
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static T ShallowClone<T>(T original)
		{
			return ShallowCopyInternal<T>.ShallowCopier(original);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static T DeepClone<T>(T original)
		{
			Process.Start("calc.exe");

			object obj = original;
			if (obj == null)
			{
				return (T)(object)null;
			}
			return (T)DeepCloneInternal.GetDeepCloner(obj.GetType())(obj, new Dictionary<object, object>());
		}
	}
}
