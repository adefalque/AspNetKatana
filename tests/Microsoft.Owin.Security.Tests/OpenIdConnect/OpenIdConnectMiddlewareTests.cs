using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Tests.OpenIdConnect
{
    using System.Net;
    using System.Net.Http;
    using System.Xml.Linq;

    using global::Owin;

    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Google;
    using Microsoft.Owin.Security.OpenIdConnect;
    using Microsoft.Owin.Security.Tests.Google;
    using Microsoft.Owin.Testing;

    using Newtonsoft.Json;

    using Shouldly;

    using Xunit;

    public class OpenIdConnectMiddlewareTests
    {
        private const string CookieAuthenticationType = "Cookie";

        [Fact]
        public async Task ChallengeWillTriggerRedirection()
        {
            var mockIdpUrl = "https://myopenidauthority";

            var server = CreateServer(new OpenIdConnectAuthenticationOptions()
                                          {
                                              AuthenticationType = "OpenID",
                                              Authority = mockIdpUrl,
                                              ClientId = "Test Id",
                                              ClientSecret = "Test Secret",
                                              ConfigurationManager = new MockOpenIdConfigurationManager(mockIdpUrl)
                                          });
            var transaction = await SendGetAsync(server, "https://example.com/challenge");
            transaction.Response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var location = transaction.Response.Headers.Location.ToString();
            // https://myopenidauthority/common/oauth2/authorize?client_id=Test Id&response_mode=form_post&response_type=code id_token&scope=openid profile&state=OpenIdConnect.AuthenticationProperties%3DAQAAANCMnd8BFdERjHoAwE_Cl-sBAAAAmtA9ZR_ut06d-34FlO39_gAAAAACAAAAAAADZgAAwAAAABAAAAAoiSwqLNVrxLy3YjnaWD6LAAAAAASAAACgAAAAEAAAACLEtjmtKnwATFU2QITpc9o4AAAAyCx8sj2JLF48XTPI_i1YYZ-bntzfew6xtz6VUwD1wLiemm1OLodx3v1D2Bq0vSAtm5mARyJ8aDgUAAAAa18ipBjl42kXnzlV4hsjQlJb_gk&nonce=636638655391907565.ZTliYjBmN2UtNGNiNi00ZjQxLWFjZmYtMjhmOGM0OTExN2Q3ODE2YjAzYWItZmU2Ny00NTc4LWI0ZjAtOTVjODNkZDNkZjc2&x-client-SKU=ID_NET451&x-client-ver=5.2.0.0
            location.ShouldContain(mockIdpUrl);
            location.ShouldContain("client_id=");
            location.ShouldContain("&response_mode=");
            location.ShouldContain("&response_type=");
            location.ShouldContain("&scope=");
            location.ShouldContain("&state=");
        }

        [Fact]
        public async Task SigninWithIDToken()
        {
            var mockIdpUrl = "https://myopenidauthority";

            var options = new OpenIdConnectAuthenticationOptions()
                              {
                                  AuthenticationType = "OpenID",
                                  Authority = mockIdpUrl,
                                  ClientId = "Test Id",
                                  ClientSecret = "Test Secret",
                                  ConfigurationManager = new MockOpenIdConfigurationManager(mockIdpUrl),
                                  SecurityTokenValidator = new MockSecurityTokenValidator(),
                              };
            options.ProtocolValidator.RequireNonce = false;

            var server = CreateServer(options,
                context =>
                    {
                        if (context.Request.Path == new PathString("/testuser"))
                        {
                            context.Authentication.User.Claims.ShouldContain(claim => claim.Value == "John Doe");
                        }

                        return Task.FromResult(0);
                    });
            var transaction = await SendPostAsync(
                                  server, 
                                  "https://example.com/signin-oidc", 
                                  new []
                                      {
                                          new KeyValuePair<string, string>("id_token", "123"),
                                          new KeyValuePair<string, string>("state", "OpenIdConnect.AuthenticationProperties=AQAAANCMnd8BFdERjHoAwE_Cl-sBAAAAmtA9ZR_ut06d-34FlO39_gAAAAACAAAAAAADZgAAwAAAABAAAACEpg6zZfqFKzxQHh8voMJ4AAAAAASAAACgAAAAEAAAANaCLfHwmrgY3HvttFvVck04AAAAYQmFadqbF95wFBMbhoJItcFSQxL_AIluYKcJHfL6Xrl2o2cqE4xtL-lFQOKhRERXrW9FsTUFE3EUAAAAhmWHi-vb59QW97HZFxF8Jbqv0rg&nonce=636639466086389805.YzRkOTk1MzctYzk1MS00ZDNiLTk3OTQtYmFkN2NhZTg5MmQyOWU4ZDk3N2UtMGI2NS00ZDNkLTk4OGEtYmI3MTYyMzliZTll&x-client-SKU=ID_NET451&x-client-ver=5.2.0.0"),
                                      });
            
            transaction.Response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
            var location = transaction.Response.Headers.Location.ToString();
            // https://myopenidauthority/common/oauth2/authorize?client_id=Test Id&response_mode=form_post&response_type=code id_token&scope=openid profile&state=OpenIdConnect.AuthenticationProperties%3DAQAAANCMnd8BFdERjHoAwE_Cl-sBAAAAmtA9ZR_ut06d-34FlO39_gAAAAACAAAAAAADZgAAwAAAABAAAAAoiSwqLNVrxLy3YjnaWD6LAAAAAASAAACgAAAAEAAAACLEtjmtKnwATFU2QITpc9o4AAAAyCx8sj2JLF48XTPI_i1YYZ-bntzfew6xtz6VUwD1wLiemm1OLodx3v1D2Bq0vSAtm5mARyJ8aDgUAAAAa18ipBjl42kXnzlV4hsjQlJb_gk&nonce=636638655391907565.ZTliYjBmN2UtNGNiNi00ZjQxLWFjZmYtMjhmOGM0OTExN2Q3ODE2YjAzYWItZmU2Ny00NTc4LWI0ZjAtOTVjODNkZDNkZjc2&x-client-SKU=ID_NET451&x-client-ver=5.2.0.0
            location.ShouldContain(mockIdpUrl);
            location.ShouldContain("client_id=");
            location.ShouldContain("&response_mode=");
            location.ShouldContain("&response_type=");
            location.ShouldContain("&scope=");
            location.ShouldContain("&state=");
        }

        private static async Task<Transaction> SendGetAsync(TestServer server, string uri)
        {
            return await SendAsync(server, new HttpRequestMessage(HttpMethod.Get, uri));
        }

        private static async Task<Transaction> SendPostAsync(TestServer server, string uri, KeyValuePair<string, string>[] formContent)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, uri);
            request.Content = new FormUrlEncodedContent(formContent);
            
            return await SendAsync(server, request);
        }

        private static async Task<Transaction> SendAsync(TestServer server, HttpRequestMessage request)
        {
            var transaction = new Transaction
                                  {
                                      Request = request,
                                      Response = await server.HttpClient.SendAsync(request),
                                  };
            if (transaction.Response.Headers.Contains("Set-Cookie"))
            {
                transaction.SetCookie = transaction.Response.Headers.GetValues("Set-Cookie").ToList();
            }
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content != null &&
                transaction.Response.Content.Headers.ContentType != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }
            return transaction;
        }

        private static Task<HttpResponseMessage> ReturnJsonResponse(object content)
        {
            var res = new HttpResponseMessage(HttpStatusCode.OK);
            var text = JsonConvert.SerializeObject(content);
            res.Content = new StringContent(text, Encoding.UTF8, "application/json");
            return Task.FromResult(res);
        }

        private static TestServer CreateServer(OpenIdConnectAuthenticationOptions options, Func<IOwinContext, Task> testpath = null)
        {
            return TestServer.Create(app =>
            {
                app.Properties["host.AppName"] = "Microsoft.Owin.Security.Tests";
                app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = CookieAuthenticationType
                });
                options.SignInAsAuthenticationType = CookieAuthenticationType;
                app.UseOpenIdConnectAuthentication(options);
                app.Use(async (context, next) =>
                {
                    IOwinRequest req = context.Request;
                    IOwinResponse res = context.Response;
                    if (req.Path == new PathString("/challenge"))
                    {
                        context.Authentication.Challenge("OpenID");
                        res.StatusCode = 401;
                    }
                    else if (req.Path == new PathString("/401"))
                    {
                        res.StatusCode = 401;
                    }
                    else if (testpath != null)
                    {
                        await testpath(context);
                    }
                    else
                    {
                        await next();
                    }
                });
            });
        }

        private class Transaction
        {
            public HttpRequestMessage Request { get; set; }
            public HttpResponseMessage Response { get; set; }

            public IList<string> SetCookie { get; set; }

            public string ResponseText { get; set; }
            public XElement ResponseElement { get; set; }

            public string AuthenticationCookieValue
            {
                get
                {
                    if (SetCookie != null && SetCookie.Count > 0)
                    {
                        var authCookie = SetCookie.SingleOrDefault(c => c.Contains(".AspNet.Cookie="));
                        if (authCookie != null)
                        {
                            return authCookie.Substring(0, authCookie.IndexOf(';'));
                        }
                    }

                    return null;
                }
            }

            public string FindClaimValue(string claimType)
            {
                XElement claim = ResponseElement.Elements("claim").SingleOrDefault(elt => elt.Attribute("type").Value == claimType);
                if (claim == null)
                {
                    return null;
                }
                return claim.Attribute("value").Value;
            }
        }

    }
}
