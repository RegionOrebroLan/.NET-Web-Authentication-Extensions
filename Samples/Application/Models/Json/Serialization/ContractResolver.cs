using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Application.Models.Json.Serialization
{
	public class ContractResolver : DefaultContractResolver
	{
		#region Methods

		protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
		{
			return base.CreateProperties(type, memberSerialization).OrderBy(jsonProperty => jsonProperty.PropertyName).ToList();
		}

		/// <summary>
		/// Remove empty arrays and strings.
		/// </summary>
		protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
		{
			var property = base.CreateProperty(member, memberSerialization);

			if(property.PropertyType != typeof(string) && property.PropertyType.GetInterface(nameof(IEnumerable)) != null)
				property.ShouldSerialize = instance => (instance?.GetType().GetProperty(property.PropertyName)?.GetValue(instance) as IEnumerable<object>)?.Count() > 0;

			return property;
		}

		#endregion
	}
}