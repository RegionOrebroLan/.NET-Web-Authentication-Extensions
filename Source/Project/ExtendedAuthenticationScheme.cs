using System;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Extensions;

namespace RegionOrebroLan.Web.Authentication
{
	public class ExtendedAuthenticationScheme : AuthenticationScheme, IAuthenticationScheme
	{
		#region Fields

		private static readonly SchemeRegistrationOptions _defaultOptions = new SchemeRegistrationOptions();
		private string _icon;
		private AuthenticationSchemeKind? _kind;
		private static readonly ConcurrentDictionary<Type, AuthenticationSchemeKind> _kindCache = new ConcurrentDictionary<Type, AuthenticationSchemeKind>();

		#endregion

		#region Constructors

		public ExtendedAuthenticationScheme(string displayName, Type handlerType, string name, SchemeRegistrationOptions options) : base(name, displayName, handlerType)
		{
			this.Options = options;
		}

		#endregion

		#region Properties

		protected internal virtual SchemeRegistrationOptions DefaultOptions => _defaultOptions;
		public virtual bool Enabled => this.Options?.Enabled ?? false;
		public virtual string Icon => this._icon ??= (this.Options?.Icon ?? this.Name).ToLowerInvariant();
		public virtual int Index => this.Options?.Index ?? this.DefaultOptions.Index;
		public virtual bool Interactive => this.Options?.Interactive ?? false;

		public virtual AuthenticationSchemeKind Kind
		{
			get
			{
				this._kind ??= this.KindCache.GetOrAdd(this.HandlerType, type =>
				{
					if(!type.IsAuthenticationHandlerType())
						return AuthenticationSchemeKind.Undefined;

					if(type.IsCertificateAuthenticationHandlerType())
						return AuthenticationSchemeKind.Certificate;

					if(type.IsCookieAuthenticationHandlerType())
						return AuthenticationSchemeKind.Cookie;

					if(type.IsRemoteAuthenticationHandlerType())
						return AuthenticationSchemeKind.Remote;

					// ReSharper disable ConvertIfStatementToReturnStatement
					if(type.IsWindowsAuthenticationHandlerType())
						return AuthenticationSchemeKind.Windows;
					// ReSharper restore ConvertIfStatementToReturnStatement

					return AuthenticationSchemeKind.Undefined;
				});

				return this._kind.Value;
			}
		}

		protected internal virtual ConcurrentDictionary<Type, AuthenticationSchemeKind> KindCache => _kindCache;
		protected internal virtual SchemeRegistrationOptions Options { get; }
		public virtual bool SignOutSupport => this.Options?.SignOutSupport ?? this.DefaultOptions.SignOutSupport;

		#endregion
	}
}