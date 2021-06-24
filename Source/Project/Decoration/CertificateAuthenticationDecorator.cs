using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Logging.Extensions;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Security.Cryptography;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	/// <inheritdoc />
	[ServiceConfiguration(Lifetime = ServiceLifetime.Transient)]
	public class CertificateAuthenticationDecorator : IncludeClaimDecorator
	{
		#region Fields

		private const string _certificateSourcePrefix = "Certificate.";

		#endregion

		#region Constructors

		public CertificateAuthenticationDecorator(IHttpContextAccessor httpContextAccessor, ILoggerFactory loggerFactory) : base(loggerFactory)
		{
			this.HttpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
		}

		#endregion

		#region Properties

		protected internal virtual string CertificateSourcePrefix => _certificateSourcePrefix;
		protected internal virtual IHttpContextAccessor HttpContextAccessor { get; }

		#endregion

		#region Methods

		public override async Task DecorateAsync(AuthenticateResult authenticateResult, string authenticationScheme, IClaimBuilderCollection claims, AuthenticationProperties properties)
		{
			try
			{
				var certificate = await this.HttpContextAccessor.HttpContext.Connection.GetClientCertificateAsync().ConfigureAwait(false);

				if(certificate == null)
				{
					this.Logger.LogErrorIfEnabled("There is not client-certificate connected.");
					return;
				}
			}
			catch(Exception exception)
			{
				const string message = "Could not decorate certificate-authentication.";

				this.Logger.LogErrorIfEnabled(exception, message);

				throw new InvalidOperationException(message, exception);
			}
		}

		[SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase")]
		protected internal virtual Func<string> GetPropertyFunction(ICertificate certificate, string propertyName)
		{
			if(certificate == null)
				throw new ArgumentNullException(nameof(certificate));

			propertyName = propertyName?.ToLowerInvariant();

			return propertyName switch
			{
				"dns" => () => certificate.GetNameInformation(X509NameType.DnsName, false),
				"dnsfromalternativename" => () => certificate.GetNameInformation(X509NameType.DnsFromAlternativeName, false),
				"email" => () => certificate.GetNameInformation(X509NameType.EmailName, false),
				"friendlyname" => () => certificate.FriendlyName,
				"issuer" => () => certificate.Issuer,
				"serialnumber" => () => certificate.SerialNumber,
				"simplename" => () => certificate.GetNameInformation(X509NameType.SimpleName, false),
				"subject" => () => certificate.Subject,
				"thumbprint" => () => certificate.Thumbprint,
				"upn" => () => certificate.GetNameInformation(X509NameType.UpnName, false),
				"url" => () => certificate.GetNameInformation(X509NameType.UrlName, false),
				_ => null,
			};
		}

		protected internal override bool TryGetSpecialSourceClaim(ClaimsPrincipal principal, string source, out IClaimBuilder claim)
		{
			if(principal == null)
				throw new ArgumentNullException(nameof(principal));

			if(base.TryGetSpecialSourceClaim(principal, source, out claim))
				return true;

			// ReSharper disable InvertIf
			if(!string.IsNullOrWhiteSpace(source) && source.StartsWith(this.CertificateSourcePrefix, StringComparison.OrdinalIgnoreCase))
			{
				var certificate = (X509Certificate2Wrapper)this.HttpContextAccessor.HttpContext.Connection.ClientCertificate;

				if(certificate == null)
				{
					this.Logger.LogWarningIfEnabled($"Could not get special source-claim for source {this.ValueAsFormatArgument(source)} because certificate is null.");
				}
				else
				{
					var propertyName = source.Substring(this.CertificateSourcePrefix.Length);

					var propertyFunction = this.GetPropertyFunction(certificate, propertyName);

					if(propertyFunction != null)
					{
						claim = new ClaimBuilder
						{
							Type = source,
							Value = propertyFunction()
						};

						claim.Issuer = claim.OriginalIssuer = certificate.Issuer;
					}
					else
					{
						this.Logger.LogDebugIfEnabled($"Could not get special source-claim for source {this.ValueAsFormatArgument(source)}.");
					}
				}

				return true;
			}
			// ReSharper restore InvertIf

			return false;
		}

		#endregion
	}
}