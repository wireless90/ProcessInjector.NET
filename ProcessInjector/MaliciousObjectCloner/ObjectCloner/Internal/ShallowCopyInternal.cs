using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace ObjectCloner.Internal
{
	internal static class ShallowCopyInternal<T>
	{
		public static readonly Func<T, T> ShallowCopier;

		static ShallowCopyInternal()
		{
			if (typeof(T).IsValueType || typeof(T) == typeof(string))
			{
				ShallowCopier = Identity;
			}
			else
			{
				ShallowCopier = CreateShallowCopyExpressionLamda().Compile();
			}
		}

		private static Expression<Func<T, T>> CreateShallowCopyExpressionLamda()
		{
			MethodInfo method = typeof(T).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic);
			ParameterExpression parameterExpression = Expression.Parameter(typeof(T), "input");
			return Expression.Lambda<Func<T, T>>(Expression.Convert(Expression.Condition(Expression.ReferenceEqual(parameterExpression, Expression.Constant(null)), Expression.Constant(null), Expression.Call(parameterExpression, method)), typeof(T)), new ParameterExpression[1] { parameterExpression });
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static T Identity(T input)
		{
			return input;
		}
	}
}
