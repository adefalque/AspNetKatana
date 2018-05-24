using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Tests.OpenIdConnect
{
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;

    using Microsoft.IdentityModel.Tokens;
    internal class MockSecurityTokenValidator : ISecurityTokenValidator
    {
        public bool HasValidatedToken { get; set; }

        public bool CanReadToken(string securityToken)
        {
            return true;
        }

        public ClaimsPrincipal ValidateToken(
            string securityToken,
            TokenValidationParameters validationParameters,
            out SecurityToken validatedToken)
        {
            Claim[] claims = new[]
                                 {
                                     new Claim("iat", "13654654"),
                                     new Claim("sub", "John Doe"),
                                     new Claim("user_email", "jdoe@test.com"),
                                     new Claim("exp", (DateTime.Now.AddHours(8) - new DateTime(1970,1,1)).TotalSeconds.ToString())
                                 };
            
            validatedToken = new JwtSecurityToken("Owin.Security.Tests.Issuer", "Owin.Security.Tests.Audience", claims);

            return new ClaimsPrincipal(new ClaimsIdentity(claims));
        }

        public bool CanValidateToken
        {
            get
            {
                return true;
            }
        }

        public int MaximumTokenSizeInBytes { get; set; }
    }
}
