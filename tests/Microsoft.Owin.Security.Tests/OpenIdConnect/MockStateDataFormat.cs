namespace Microsoft.Owin.Security.Tests.OpenIdConnect
{
    public class MockStateDataFormat : ISecureDataFormat<AuthenticationProperties>
    {
        public string Protect(AuthenticationProperties data)
        {
            return "";
        }

        public AuthenticationProperties Unprotect(string protectedText)
        {
            return new AuthenticationProperties();
        }
    }
}