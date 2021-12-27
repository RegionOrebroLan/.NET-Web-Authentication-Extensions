using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using RegionOrebroLan.Web.Authentication.Certificate;

namespace RegionOrebroLan.Web.Authentication.Extensions
{
	public static class TypeExtension
	{
		#region Methods

		public static bool IsAuthenticationHandlerType(this Type type)
		{
			return type != null && typeof(IAuthenticationHandler).IsAssignableFrom(type);
		}

		public static bool IsCertificateAuthenticationHandlerType(this Type type)
		{
			return type.IsAuthenticationHandlerType() && typeof(AuthenticationHandler<CertificateAuthenticationOptions>).IsAssignableFrom(type);
		}

		public static bool IsCookieAuthenticationHandlerType(this Type type)
		{
			return type.IsAuthenticationHandlerType() && typeof(CookieAuthenticationHandler).IsAssignableFrom(type);
		}

		public static bool IsNegotiateAuthenticationHandlerType(this Type type)
		{
			return type.IsAuthenticationHandlerType() && typeof(NegotiateHandler).IsAssignableFrom(type);
		}

		public static bool IsRemoteAuthenticationHandlerType(this Type type)
		{
			// ReSharper disable InvertIf
			if(type.IsAuthenticationHandlerType())
			{
				var remoteAuthenticationHandlerType = typeof(RemoteAuthenticationHandler<>);

				while(type != null && type != typeof(object))
				{
					var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : type;

					if(genericType == remoteAuthenticationHandlerType)
						return true;

					type = type.BaseType;
				}
			}
			// ReSharper restore InvertIf

			return false;
		}

		#endregion
	}
}