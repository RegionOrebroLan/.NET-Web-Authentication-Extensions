using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class AuthenticationSchemeExtension
	{
		#region Methods

		/// <summary>
		/// Get the options, for diagnostics, for an authentication-scheme. Claim-actions and events are removed.
		/// </summary>
		public static async Task<AuthenticationSchemeOptions> GetOptionsDiagnosticsAsync(this IAuthenticationScheme authenticationScheme, IServiceProvider serviceProvider)
		{
			if(authenticationScheme == null)
				throw new ArgumentNullException(nameof(authenticationScheme));

			if(serviceProvider == null)
				throw new ArgumentNullException(nameof(serviceProvider));

			var handlerType = authenticationScheme.HandlerType;

			while(handlerType != null)
			{
				if(handlerType.IsGenericType)
				{
					var optionsType = handlerType.GetGenericArguments().FirstOrDefault(genericArgument => typeof(AuthenticationSchemeOptions).IsAssignableFrom(genericArgument));

					if(optionsType != null)
					{
						var optionsMonitorType = typeof(IOptionsMonitor<>).MakeGenericType(optionsType);

						if(serviceProvider.GetService(optionsMonitorType) is IOptionsMonitor<AuthenticationSchemeOptions> optionsMonitor)
						{
							var options = optionsMonitor.Get(authenticationScheme.Name);

							if(options != null)
							{
								var optionsFactoryType = typeof(IOptionsFactory<>).MakeGenericType(options.GetType());

								var optionsFactory = serviceProvider.GetService(optionsFactoryType);

								// ReSharper disable All
								if(optionsFactory != null)
								{
									options = (AuthenticationSchemeOptions)optionsFactory.GetType().GetMethod("Create").Invoke(optionsFactory, new object[] { authenticationScheme.Name });

									if(options != null)
									{
										options.Events = null;

										if(options is OAuthOptions oAuthOptions)
											oAuthOptions.ClaimActions.Clear();
										else if(options is OpenIdConnectOptions openIdConnectOptions)
											openIdConnectOptions.ClaimActions.Clear();

										return await Task.FromResult(options).ConfigureAwait(false);
									}
								}
								// ReSharper restore All
							}
						}
					}
				}

				handlerType = handlerType.BaseType;
			}

			return null;
		}

		#endregion
	}
}