using System;
using Microsoft.Extensions.Configuration;

namespace RegionOrebroLan.Web.Authentication.Decoration.Extensions
{
	public static class DecoratorExtension
	{
		#region Methods

		public static void Initialize(this IDecorator decorator, IConfigurationSection optionsConfiguration)
		{
			if(decorator == null)
				throw new ArgumentNullException(nameof(decorator));

			decorator.InitializeAsync(optionsConfiguration).Wait();
		}

		#endregion
	}
}