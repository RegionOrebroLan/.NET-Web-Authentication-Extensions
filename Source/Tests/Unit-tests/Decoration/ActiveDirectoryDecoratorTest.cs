using System;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RegionOrebroLan.Security.Claims;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration;
using RegionOrebroLan.Web.Authentication.DirectoryServices;
using TestHelpers.Mocks.Logging;

namespace UnitTests.Decoration
{
	[TestClass]
	public class ActiveDirectoryDecoratorTest : DecoratorTestBase
	{
		#region Fields

		private IOptionsMonitor<ExtendedAuthenticationOptions> _authenticationOptionsMonitor;

		#endregion

		#region Properties

		protected internal virtual IOptionsMonitor<ExtendedAuthenticationOptions> AuthenticationOptionsMonitor
		{
			get
			{
				if(this._authenticationOptionsMonitor == null)
				{
					var authenticationOptions = new ExtendedAuthenticationOptions();

					var authenticationOptionsMonitorMock = new Mock<IOptionsMonitor<ExtendedAuthenticationOptions>>();

					authenticationOptionsMonitorMock.Setup(authenticationOptionsMonitor => authenticationOptionsMonitor.CurrentValue).Returns(authenticationOptions);

					this._authenticationOptionsMonitor = authenticationOptionsMonitorMock.Object;
				}

				return this._authenticationOptionsMonitor;
			}
		}

		#endregion

		#region Methods

		protected internal virtual async Task<ActiveDirectoryDecorator> CreateDecoratorAsync(string fileName, ILoggerFactory loggerFactory)
		{
			var decorator = new ActiveDirectoryDecorator(Mock.Of<IActiveDirectory>(), this.AuthenticationOptionsMonitor, loggerFactory);

			var configuration = await this.CreateConfigurationAsync(fileName);

			await decorator.InitializeAsync(configuration);

			return await Task.FromResult(decorator);
		}

		[TestMethod]
		[ExpectedException(typeof(InvalidOperationException))]
		public async Task CreateFilterAsync_SecurityIdentifier_IfThereIsNoPrimarySidClaim_ShouldThrowAnInvalidOperationException()
		{
			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("SecurityIdentifier", loggerFactory);

				try
				{
					await decorator.CreateFilterAsync(new ClaimBuilderCollection());
				}
				catch(InvalidOperationException invalidOperationException)
				{
					if(string.Equals(invalidOperationException.InnerException?.Message, "Could not find any security-identifier-claims with claim-type \"primarysid\".", StringComparison.Ordinal))
						throw;
				}
			}
		}

		[TestMethod]
		public async Task CreateFilterAsync_SecurityIdentifier_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "primarysid", Value = "primarysid-value" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("SecurityIdentifier", loggerFactory);

				var filter = await decorator.CreateFilterAsync(claims);

				Assert.AreEqual("(|(objectSid=primarysid-value))", filter);
			}
		}

		[TestMethod]
		public async Task CreateFilterAsync_UserPrincipalNameWithEmailFallback_ShouldWorkProperly()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = JwtClaimTypes.Email, Value = "first-name.last-name@example.org" },
				new ClaimBuilder { Type = "upn", Value = "upn@example.org" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("UserPrincipalNameWithEmailFallback", loggerFactory);

				var filter = await decorator.CreateFilterAsync(claims);

				Assert.AreEqual("(|(userPrincipalName=upn@example.org)(userPrincipalName=first-name.last-name@example.org))", filter);
			}
		}

		[TestMethod]
		[ExpectedException(typeof(FormatException))]
		public async Task CreateFilterFromFilterFormatAsync_IfTheFormatArgumentsAreNotCorrect_ShouldThrowAFormatException()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "first-claim", Value = "first-claim-value" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("FilterFormat-Invalid", loggerFactory);

				await decorator.CreateFilterFromFilterFormatAsync(claims);
			}
		}

		[TestMethod]
		public async Task CreateFilterFromFilterFormatAsync_Test1()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "first-claim", Value = "first-claim-value" },
				new ClaimBuilder { Type = "second-claim", Value = "second-claim-value" },
				new ClaimBuilder { Type = "third-claim", Value = "third-claim-value" },
				new ClaimBuilder { Type = "fourth-claim", Value = "fourth-claim-value" },
				new ClaimBuilder { Type = "fifth-claim", Value = "fifth-claim-value" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("FilterFormat-1", loggerFactory);

				var filter = await decorator.CreateFilterFromFilterFormatAsync(claims);

				Assert.AreEqual("(|(first=first-claim-value)(second=second-claim-value)(third=third-claim-value)(fourth=fourth-claim-value)(fifth=fifth-claim-value))", filter);
			}
		}

		[TestMethod]
		public async Task CreateFilterFromFilterFormatAsync_Test2()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "first-claim", Value = "first-claim-value" },
				new ClaimBuilder { Type = "second-claim", Value = "second-claim-value" },
				new ClaimBuilder { Type = "third-claim", Value = "third-claim-value" },
				new ClaimBuilder { Type = "fourth-claim", Value = "fourth-claim-value" },
				new ClaimBuilder { Type = "fifth-claim", Value = "fifth-claim-value" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("FilterFormat-2", loggerFactory);

				var filter = await decorator.CreateFilterFromFilterFormatAsync(claims);

				Assert.AreEqual("(|(first=third-claim-value)(second=third-claim-value)(third=third-claim-value)(fourth=third-claim-value)(fifth=third-claim-value))", filter);
			}
		}

		[TestMethod]
		public async Task CreateFilterFromFilterFormatAsync_Test3()
		{
			var claims = new ClaimBuilderCollection
			{
				new ClaimBuilder { Type = "first-claim", Value = "first-claim-value" }
			};

			using(var loggerFactory = LoggerFactoryMock.Create())
			{
				var decorator = await this.CreateDecoratorAsync("FilterFormat-3", loggerFactory);

				var filter = await decorator.CreateFilterFromFilterFormatAsync(claims);

				Assert.AreEqual("(|(first=first-claim-value)(second=first-claim-value)(third=first-claim-value)(fourth=first-claim-value)(fifth=first-claim-value))", filter);
			}
		}

		#endregion
	}
}