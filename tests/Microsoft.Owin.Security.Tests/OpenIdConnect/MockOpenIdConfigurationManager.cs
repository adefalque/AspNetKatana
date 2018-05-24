namespace Microsoft.Owin.Security.Tests.OpenIdConnect
{
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;

    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;

    internal class MockOpenIdConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private readonly Uri authorityUri;

        public MockOpenIdConfigurationManager(string authority)
        {
            this.authorityUri = new Uri(authority);
        }

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            return await Task.FromResult(new OpenIdConnectConfiguration()
            {
                AuthorizationEndpoint = new Uri(this.authorityUri, "/common/oauth2/authorize").ToString()
            });
        }

        public void RequestRefresh()
        {
            throw new System.NotImplementedException();
        }
    }
}