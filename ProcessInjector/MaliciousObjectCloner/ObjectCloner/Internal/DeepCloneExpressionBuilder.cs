using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Reflection;

namespace ObjectCloner.Internal
{
	internal class DeepCloneExpressionBuilder
	{
		private static readonly Type _typeOfObject = typeof(object);

		private readonly Type _typeOfT;

		private readonly ParameterExpression _originalParameter;

		private readonly ParameterExpression _originalVariable;

		private readonly ParameterExpression _dictionaryParameter;

		private readonly ParameterExpression _cloneVariable;

		private readonly LabelTarget _returnTarget;

		private readonly MethodInfo itemClonerGetter = typeof(DeepCloneInternal).GetMethod("GetDeepCloner", BindingFlags.Static | BindingFlags.Public);

		private readonly MethodInfo invokeMethod = typeof(DeepCloner).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.Public);

		private readonly MethodInfo getTypeMethod = _typeOfObject.GetMethod("GetType", BindingFlags.Instance | BindingFlags.Public);

		private readonly MethodInfo arrayCloneMethod = typeof(Array).GetMethod("Clone", BindingFlags.Instance | BindingFlags.Public);

		public DeepCloneExpressionBuilder(Type typeOfT)
		{
			_typeOfT = typeOfT;
			_dictionaryParameter = Expression.Parameter(typeof(Dictionary<object, object>), "dict");
			_returnTarget = Expression.Label(_typeOfObject);
			_cloneVariable = Expression.Variable(_typeOfT, "clone");
			_originalParameter = Expression.Parameter(_typeOfObject, "original");
			_originalVariable = Expression.Parameter(_typeOfT, "originalCasted");
		}

		public Expression<DeepCloner> Build()
		{
			List<Expression> list = new List<Expression>(10);
			list.Add(Expression.Assign(_originalVariable, Expression.Convert(_originalParameter, _typeOfT)));
			if (!_typeOfT.IsValueType)
			{
				list.Add(CreateReturnIfNullExpression());
				list.Add(CreateReturnIfInDictionaryExpression());
			}
			if (_typeOfT.IsArray)
			{
				list.Add(CreateArrayCloneExpression());
			}
			else
			{
				list.Add(CreateMemberwiseCloneExpression());
				if (!_typeOfT.IsValueType)
				{
					list.Add(CreateAddToDictionaryExpression());
				}
				list.AddRange(CreateFieldCopyExpressions());
			}
			list.Add(Expression.Label(_returnTarget, Expression.Convert(_cloneVariable, _typeOfObject)));
			return Expression.Lambda<DeepCloner>(Expression.Block(new ParameterExpression[2] { _cloneVariable, _originalVariable }, list), new ParameterExpression[2] { _originalParameter, _dictionaryParameter });
		}

		private ConditionalExpression CreateReturnIfNullExpression()
		{
			return Expression.IfThen(Expression.ReferenceEqual(_originalVariable, Expression.Constant(null)), Expression.Return(_returnTarget, Expression.Constant(null, _typeOfObject)));
		}

		private Expression CreateReturnIfInDictionaryExpression()
		{
			MethodInfo method = typeof(Dictionary<object, object>).GetMethod("TryGetValue", BindingFlags.Instance | BindingFlags.Public);
			ParameterExpression parameterExpression = Expression.Variable(_typeOfObject);
			return Expression.Block(new ParameterExpression[1] { parameterExpression }, Expression.IfThen(Expression.IsTrue(Expression.Call(_dictionaryParameter, method, _originalVariable, parameterExpression)), Expression.Return(_returnTarget, parameterExpression)));
		}

		private Expression CreateArrayCloneExpression()
		{
			Type elementType = _typeOfT.GetElementType();
			if (TypeHelper.CanSkipDeepClone(elementType))
			{
				return Expression.Assign(_cloneVariable, Expression.Convert(Expression.Call(_originalVariable, arrayCloneMethod), _typeOfT));
			}
			ParameterExpression parameterExpression = Expression.Variable(typeof(int));
			ParameterExpression parameterExpression2 = Expression.Variable(typeof(int));
			LabelTarget labelTarget = Expression.Label();
			return Expression.Block(new ParameterExpression[2] { parameterExpression, parameterExpression2 }, Expression.Assign(parameterExpression, Expression.ArrayLength(_originalVariable)), Expression.Assign(_cloneVariable, Expression.NewArrayBounds(elementType, parameterExpression)), Expression.Assign(parameterExpression2, Expression.Constant(0)), Expression.Loop(Expression.Block(Expression.IfThen(Expression.GreaterThanOrEqual(parameterExpression2, parameterExpression), Expression.Break(labelTarget)), Expression.Assign(Expression.ArrayAccess(_cloneVariable, parameterExpression2), Expression.Convert(CreateRecursiveCallExpression(Expression.ArrayAccess(_originalVariable, parameterExpression2)), elementType)), Expression.PostIncrementAssign(parameterExpression2)), labelTarget), Expression.Return(_returnTarget, Expression.Convert(_cloneVariable, _typeOfObject)));
		}

		private Expression CreateRecursiveCallExpression(Expression objectToCopy)
		{
			return Expression.Condition(Expression.ReferenceEqual(Expression.Convert(objectToCopy, _typeOfObject), Expression.Constant(null)), Expression.Convert(Expression.Constant(null), _typeOfObject), Expression.Call(Expression.Call(null, itemClonerGetter, Expression.Call(objectToCopy, getTypeMethod)), invokeMethod, Expression.Convert(objectToCopy, _typeOfObject), _dictionaryParameter));
		}

		private Expression CreateMemberwiseCloneExpression()
		{
			MethodInfo method = _typeOfObject.GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic);
			return Expression.Assign(_cloneVariable, Expression.Convert(Expression.Call(_originalVariable, method), _typeOfT));
		}

		private Expression CreateAddToDictionaryExpression()
		{
			MethodInfo method = typeof(Dictionary<object, object>).GetMethod("Add", BindingFlags.Instance | BindingFlags.Public);
			return Expression.Call(_dictionaryParameter, method, _originalVariable, _cloneVariable);
		}

		private IEnumerable<Expression> CreateFieldCopyExpressions()
		{
			IEnumerable<FieldInfo> allFieldsDeep = _typeOfT.GetAllFieldsDeep();
			foreach (FieldInfo item in allFieldsDeep)
			{
				if (!TypeHelper.CanSkipDeepClone(item.FieldType))
				{
					MemberExpression left = Expression.Field(_cloneVariable, item);
					if (!item.IsInitOnly)
					{
						yield return Expression.Assign(left, Expression.Convert(CreateRecursiveCallExpression(Expression.Field(_originalVariable, item)), item.FieldType));
						continue;
					}
					MethodInfo method = typeof(FieldInfo).GetMethod("SetValue", new Type[2] { _typeOfObject, _typeOfObject });
					yield return Expression.Call(Expression.Constant(item), method, Expression.Convert(_cloneVariable, _typeOfObject), CreateRecursiveCallExpression(Expression.Field(_originalVariable, item)));
				}
			}
		}
	}
}
