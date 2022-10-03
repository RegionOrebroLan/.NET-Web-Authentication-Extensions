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
	[ServiceConfiguration(ServiceType = typeof(IDecorationLoader))]
	public class DecorationLoader : IDecorationLoader
	{
		#region Fields

		private IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> _authenticationDecoratorDictionary;
		private IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationPropertiesDecorator, int>>> _authenticationPropertiesDecoratorDictionary;
		private IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> _callbackDecoratorDictionary;

		#endregion

		#region Constructors

		public DecorationLoader(IOptionsMonitor<ExtendedAuthenticationOptions> optionsMonitor, IServiceProvider serviceProvider)
		{
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
			this.ServiceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

			this.OptionsChangeListener = optionsMonitor.OnChange(this.OnOptionsChanged);
		}

		#endregion

		#region Properties

		[SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> AuthenticationDecoratorDictionary
		{
			get
			{
				// ReSharper disable All
				if(this._authenticationDecoratorDictionary == null)
				{
					lock(this.AuthenticationDecoratorDictionaryLock)
					{
						if(this._authenticationDecoratorDictionary == null)
						{
							this._authenticationDecoratorDictionary = this.CreateAuthenticationDecoratorDictionary(this.OptionsMonitor.CurrentValue.AuthenticationDecorators.Values);
						}
					}
				}
				// ReSharper restore All

				return this._authenticationDecoratorDictionary;
			}
			set
			{
				lock(this.AuthenticationDecoratorDictionaryLock)
				{
					this._authenticationDecoratorDictionary = value;
				}
			}
		}

		protected internal virtual object AuthenticationDecoratorDictionaryLock { get; } = new object();

		[SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationPropertiesDecorator, int>>> AuthenticationPropertiesDecoratorDictionary
		{
			get
			{
				// ReSharper disable All
				if(this._authenticationPropertiesDecoratorDictionary == null)
				{
					lock(this.AuthenticationPropertiesDecoratorDictionaryLock)
					{
						if(this._authenticationPropertiesDecoratorDictionary == null)
						{
							this._authenticationPropertiesDecoratorDictionary = this.CreateAuthenticationPropertiesDecoratorDictionary(this.OptionsMonitor.CurrentValue.AuthenticationPropertiesDecorators.Values);
						}
					}
				}
				// ReSharper restore All

				return this._authenticationPropertiesDecoratorDictionary;
			}
			set
			{
				lock(this.AuthenticationPropertiesDecoratorDictionaryLock)
				{
					this._authenticationPropertiesDecoratorDictionary = value;
				}
			}
		}

		protected internal virtual object AuthenticationPropertiesDecoratorDictionaryLock { get; } = new object();

		[SuppressMessage("Usage", "CA2227:Collection properties should be read only")]
		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> CallbackDecoratorDictionary
		{
			get
			{
				// ReSharper disable All
				if(this._callbackDecoratorDictionary == null)
				{
					lock(this.CallbackDecoratorDictionaryLock)
					{
						if(this._callbackDecoratorDictionary == null)
						{
							this._callbackDecoratorDictionary = this.CreateAuthenticationDecoratorDictionary(this.OptionsMonitor.CurrentValue.CallbackDecorators.Values);
						}
					}
				}
				// ReSharper restore All

				return this._callbackDecoratorDictionary;
			}
			set
			{
				lock(this.CallbackDecoratorDictionaryLock)
				{
					this._callbackDecoratorDictionary = value;
				}
			}
		}

		protected internal virtual object CallbackDecoratorDictionaryLock { get; } = new object();
		protected internal virtual IDisposable OptionsChangeListener { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthenticationOptions> OptionsMonitor { get; }
		protected internal virtual IServiceProvider ServiceProvider { get; }

		#endregion

		#region Methods

		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationDecorator, int>>> CreateAuthenticationDecoratorDictionary(IEnumerable<DecoratorOptions> options)
		{
			try
			{
				return this.CreateDecoratorDictionary<IAuthenticationDecorator>(options);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException("Could not create authentication-decorator-dictionary.", exception);
			}
		}

		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<IAuthenticationPropertiesDecorator, int>>> CreateAuthenticationPropertiesDecoratorDictionary(IEnumerable<DecoratorOptions> options)
		{
			try
			{
				return this.CreateDecoratorDictionary<IAuthenticationPropertiesDecorator>(options);
			}
			catch(Exception exception)
			{
				throw new InvalidOperationException("Could not create authentication-properties-decorator-dictionary.", exception);
			}
		}

		protected internal virtual IDictionary<string, IEnumerable<KeyValuePair<T, int>>> CreateDecoratorDictionary<T>(IEnumerable<DecoratorOptions> options) where T : IDecorator
		{
			var intermediateDecoratorDictionary = new Dictionary<string, List<KeyValuePair<T, int>>>();

			foreach(var decoratorOptions in options ?? Enumerable.Empty<DecoratorOptions>())
			{
				if(!decoratorOptions.Enabled)
					continue;

				var type = Type.GetType(decoratorOptions.Type, true, true);
				var decorator = (T)this.ServiceProvider.GetRequiredService(type);
				decorator.Initialize(decoratorOptions.Options);

				foreach(var (key, value) in decoratorOptions.AuthenticationSchemes)
				{
					if(!intermediateDecoratorDictionary.TryGetValue(key, out var list))
					{
						list = new List<KeyValuePair<T, int>>();
						intermediateDecoratorDictionary.Add(key, list);
					}

					list.Add(new KeyValuePair<T, int>(decorator, value));
				}
			}

			var decoratorDictionary = new Dictionary<string, IEnumerable<KeyValuePair<T, int>>>();

			foreach(var (key, value) in intermediateDecoratorDictionary)
			{
				decoratorDictionary.Add(key, value.OrderBy(keyValuePair => keyValuePair.Value).ToArray());
			}

			return decoratorDictionary;
		}

		public virtual async Task<IEnumerable<IAuthenticationDecorator>> GetAuthenticationDecoratorsAsync(string authenticationScheme)
		{
			return await this.GetDecoratorsAsync(authenticationScheme, this.AuthenticationDecoratorDictionary).ConfigureAwait(false);
		}

		public virtual async Task<IEnumerable<IAuthenticationPropertiesDecorator>> GetAuthenticationPropertiesDecoratorsAsync(string authenticationScheme)
		{
			return await this.GetDecoratorsAsync(authenticationScheme, this.AuthenticationPropertiesDecoratorDictionary).ConfigureAwait(false);
		}

		public virtual async Task<IEnumerable<IAuthenticationDecorator>> GetCallbackDecoratorsAsync(string authenticationScheme)
		{
			return await this.GetDecoratorsAsync(authenticationScheme, this.CallbackDecoratorDictionary).ConfigureAwait(false);
		}

		protected internal virtual async Task<IEnumerable<T>> GetDecoratorsAsync<T>(string authenticationScheme, IDictionary<string, IEnumerable<KeyValuePair<T, int>>> dictionary) where T : IDecorator
		{
			if(authenticationScheme == null)
				throw new ArgumentNullException(nameof(authenticationScheme));

			if(dictionary == null)
				throw new ArgumentNullException(nameof(dictionary));

			var decorators = new List<KeyValuePair<T, int>>();

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

		protected internal virtual void OnOptionsChanged(ExtendedAuthenticationOptions options, string name)
		{
			this.AuthenticationDecoratorDictionary = null;
			this.AuthenticationPropertiesDecoratorDictionary = null;
			this.CallbackDecoratorDictionary = null;
		}

		#endregion

		#region Other members

		#region Finalizers

		~DecorationLoader()
		{
			this.OptionsChangeListener?.Dispose();
		}

		#endregion

		#endregion
	}
}