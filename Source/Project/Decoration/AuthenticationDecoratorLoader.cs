using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RegionOrebroLan.DependencyInjection;
using RegionOrebroLan.Extensions;
using RegionOrebroLan.Web.Authentication.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration.Configuration;
using RegionOrebroLan.Web.Authentication.Decoration.Extensions;

namespace RegionOrebroLan.Web.Authentication.Decoration
{
	[ServiceConfiguration(ServiceType = typeof(IAuthenticationDecoratorLoader))]
	public class AuthenticationDecoratorLoader : IAuthenticationDecoratorLoader
	{
		#region Fields

		private IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> _decoratorDictionary;
		private IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> _postDecoratorDictionary;

		#endregion

		#region Constructors

		public AuthenticationDecoratorLoader(IOptionsMonitor<ExtendedAuthenticationOptions> optionsMonitor, IServiceProvider serviceProvider)
		{
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
			this.ServiceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

			this.OptionsChangeListener = optionsMonitor.OnChange(this.OnOptionsChanged);
		}

		#endregion

		#region Properties

		[SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> DecoratorDictionary
		{
			get
			{
				// ReSharper disable All
				if(this._decoratorDictionary == null)
				{
					lock(this.DecoratorDictionaryLock)
					{
						if(this._decoratorDictionary == null)
						{
							this._decoratorDictionary = this.CreateDecoratorDictionary(this.OptionsMonitor.CurrentValue.Decorators.Values);
						}
					}
				}
				// ReSharper restore All

				return this._decoratorDictionary;
			}
			set
			{
				lock(this.DecoratorDictionaryLock)
				{
					this._decoratorDictionary = value;
				}
			}
		}

		protected internal virtual object DecoratorDictionaryLock { get; } = new object();
		protected internal virtual IDisposable OptionsChangeListener { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthenticationOptions> OptionsMonitor { get; }

		[SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> PostDecoratorDictionary
		{
			get
			{
				// ReSharper disable All
				if(this._postDecoratorDictionary == null)
				{
					lock(this.PostDecoratorDictionaryLock)
					{
						if(this._postDecoratorDictionary == null)
						{
							this._postDecoratorDictionary = this.CreateDecoratorDictionary(this.OptionsMonitor.CurrentValue.PostDecorators.Values);
						}
					}
				}
				// ReSharper restore All

				return this._postDecoratorDictionary;
			}
			set
			{
				lock(this.PostDecoratorDictionaryLock)
				{
					this._postDecoratorDictionary = value;
				}
			}
		}

		protected internal virtual object PostDecoratorDictionaryLock { get; } = new object();
		protected internal virtual IServiceProvider ServiceProvider { get; }

		#endregion

		#region Methods

		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> CreateDecoratorDictionary(IEnumerable<AuthenticationDecoratorOptions> options)
		{
			try
			{
				var intermediateDecoratorDictionary = new Dictionary<string, List<KeyValuePair<IAuthenticationDecorator, int>>>();

				foreach(var decoratorOptions in options ?? Enumerable.Empty<AuthenticationDecoratorOptions>())
				{
					if(!decoratorOptions.Enabled)
						continue;

					var type = Type.GetType(decoratorOptions.Type, true, true);
					var decorator = (IAuthenticationDecorator) this.ServiceProvider.GetRequiredService(type);
					decorator.Initialize(decoratorOptions.Options);

					foreach(var (key, value) in decoratorOptions.AuthenticationSchemes)
					{
						if(!intermediateDecoratorDictionary.TryGetValue(key, out var list))
						{
							list = new List<KeyValuePair<IAuthenticationDecorator, int>>();
							intermediateDecoratorDictionary.Add(key, list);
						}

						list.Add(new KeyValuePair<IAuthenticationDecorator, int>(decorator, value));
					}
				}

				var decoratorDictionary = new Dictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>>();

				foreach(var (key, value) in intermediateDecoratorDictionary)
				{
					decoratorDictionary.Add(key, value.OrderBy(keyValuePair => keyValuePair.Value).ToArray());
				}

				return decoratorDictionary;
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException("Could not create decorator-dictionary.", exception);
			}
		}

		public virtual async Task<IEnumerable<IAuthenticationDecorator>> GetDecoratorsAsync(string authenticationScheme)
		{
			return await this.GetDecoratorsAsync(authenticationScheme, this.DecoratorDictionary).ConfigureAwait(false);
		}

		protected internal virtual async Task<IEnumerable<IAuthenticationDecorator>> GetDecoratorsAsync(string authenticationScheme, IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> dictionary)
		{
			if(authenticationScheme == null)
				throw new ArgumentNullException(nameof(authenticationScheme));

			if(dictionary == null)
				throw new ArgumentNullException(nameof(dictionary));

			var decorators = new List<KeyValuePair<IAuthenticationDecorator, int>>();

			foreach(var key in dictionary.Keys)
			{
				if(key == null)
					continue;

				if(authenticationScheme.Like(key))
					decorators.AddRange(dictionary[key]);
			}

			decorators.Sort((first, second) => first.Value.CompareTo(second.Value));

			return await Task.FromResult(decorators.Select(keyValuePair => keyValuePair.Key).ToArray()).ConfigureAwait(false);
		}

		public virtual async Task<IEnumerable<IAuthenticationDecorator>> GetPostDecoratorsAsync(string authenticationScheme)
		{
			return await this.GetDecoratorsAsync(authenticationScheme, this.PostDecoratorDictionary).ConfigureAwait(false);
		}

		protected internal virtual void OnOptionsChanged(ExtendedAuthenticationOptions options, string name)
		{
			this.DecoratorDictionary = null;
			this.PostDecoratorDictionary = null;
		}

		#endregion

		#region Other members

		#region Finalizers

		~AuthenticationDecoratorLoader()
		{
			this.OptionsChangeListener?.Dispose();
		}

		#endregion

		#endregion
	}
}