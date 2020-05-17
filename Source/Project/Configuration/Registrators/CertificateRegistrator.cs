using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using RegionOrebroLan.Web.Authentication.Certificate;

namespace RegionOrebroLan.Web.Authentication.Configuration.Registrators
{
	public class CertificateRegistrator : Registrator
	{
		#region Methods

		public override void Add(AuthenticationBuilder authenticationBuilder, IConfiguration configuration, string name, SchemeRegistrationOptions schemeRegistrationOptions)
		{
			if(authenticationBuilder == null)
				throw new ArgumentNullException(nameof(authenticationBuilder));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			if(schemeRegistrationOptions == null)
				throw new ArgumentNullException(nameof(schemeRegistrationOptions));

			//authenticationBuilder.Services.Configure<CertificateAuthenticationOptions>(name, options => { this.Bind(configuration, options, schemeRegistrationOptions); });

			authenticationBuilder.AddCertificate(name, schemeRegistrationOptions.DisplayName, options => { this.Bind(configuration, options, schemeRegistrationOptions); });
		}

		#endregion
	}
}