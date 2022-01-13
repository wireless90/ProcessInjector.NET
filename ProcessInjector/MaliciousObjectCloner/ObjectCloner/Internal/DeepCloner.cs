using System.Collections.Generic;

namespace ObjectCloner.Internal
{
	internal delegate object DeepCloner(object original, Dictionary<object, object> dict);
}
