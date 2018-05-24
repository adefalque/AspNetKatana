﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Notifications;

namespace Microsoft.Owin.Security.OpenIdConnect
{
    /// <summary>
    /// A per-request authentication handler for the OpenIdConnectAuthenticationMiddleware.
    /// </summary>
    public class OpenIdConnectAuthenticationHandler : AuthenticationHandler<OpenIdConnectAuthenticationOptions>
    {
        private const string HandledResponse = "HandledResponse";
        private const string NonceProperty = "N";

        private readonly ILogger _logger;
        private OpenIdConnectConfiguration _configuration;

        protected HttpClient Backchannel
        {
            get
            {
                return Options.Backchannel;
            }
        }

        /// <summary>
        /// Creates a new OpenIdConnectAuthenticationHandler
        /// </summary>
        /// <param name="logger"></param>
        public OpenIdConnectAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        private string CurrentUri
        {
            get
            {
                return Request.Scheme +
                       Uri.SchemeDelimiter +
                       Request.Host +
                       Request.PathBase +
                       Request.Path +
                       Request.QueryString;
            }
        }

        /// <summary>
        /// Handles Signout
        /// </summary>
        /// <returns></returns>
        protected override async Task ApplyResponseGrantAsync()
        {
            AuthenticationResponseRevoke signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (signout != null)
            {
                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
                }

                OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage()
                {
                    IssuerAddress = _configuration.EndSessionEndpoint ?? string.Empty,
                    RequestType = OpenIdConnectRequestType.Logout,
                };

                // Set End_Session_Endpoint in order:
                // 1. properties.Redirect
                // 2. Options.Wreply
                AuthenticationProperties properties = signout.Properties;
                if (properties != null && !string.IsNullOrEmpty(properties.RedirectUri))
                {
                    openIdConnectMessage.PostLogoutRedirectUri = properties.RedirectUri;
                }
                else if (!string.IsNullOrWhiteSpace(Options.PostLogoutRedirectUri))
                {
                    openIdConnectMessage.PostLogoutRedirectUri = Options.PostLogoutRedirectUri;
                }

                var notification = new RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };
                await Options.Notifications.RedirectToIdentityProvider(notification);

                if (!notification.HandledResponse)
                {
                    string redirectUri = notification.ProtocolMessage.CreateLogoutRequestUrl();
                    if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                    {
                        _logger.WriteWarning("The logout redirect URI is malformed: " + redirectUri);
                    }
                    Response.Redirect(redirectUri);
                }
            }
        }

        /// <summary>
        /// Handles SignIn
        /// </summary>
        /// <returns></returns>
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge == null)
                {
                    return;
                }

                // order for redirect_uri
                // 1. challenge.Properties.RedirectUri
                // 2. CurrentUri
                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = CurrentUri;
                }

                // this value will be passed to the AuthorizationCodeReceivedNotification
                if (!string.IsNullOrWhiteSpace(Options.RedirectUri))
                {
                    properties.Dictionary.Add(OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey, Options.RedirectUri);
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
                }

                OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage
                {
                    ClientId = Options.ClientId,
                    IssuerAddress = _configuration.AuthorizationEndpoint ?? string.Empty,
                    RedirectUri = Options.RedirectUri,
                    RequestType = OpenIdConnectRequestType.Authentication,
                    Resource = Options.Resource,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = Options.ResponseType,
                    Scope = Options.Scope,
                    State = OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey + "=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(properties)),
                };

                if (Options.ProtocolValidator.RequireNonce)
                {
                    AddNonceToMessage(openIdConnectMessage);
                }

                var notification = new RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };

                await Options.Notifications.RedirectToIdentityProvider(notification);

                if (!notification.HandledResponse)
                {
                    string redirectUri = notification.ProtocolMessage.CreateAuthenticationRequestUrl();
                    if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                    {
                        _logger.WriteWarning("The authenticate redirect URI is malformed: " + redirectUri);
                    }
                    Response.Redirect(redirectUri);
                }
            }

            return;
        }

        /// <summary>
        /// Invoked to process incoming authentication messages.
        /// </summary>
        /// <returns>An <see cref="AuthenticationTicket"/> if successful.</returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Allow login to be constrained to a specific path. Need to make this runtime configurable.
            if (Options.CallbackPath.HasValue && Options.CallbackPath != (Request.PathBase + Request.Path))
            {
                return null;
            }

            OpenIdConnectMessage openIdConnectMessage = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrWhiteSpace(Request.ContentType)
                // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    _logger.WriteVerbose("Buffering request body");
                    // Buffer in case this body was not meant for us.
                    MemoryStream memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }

                IFormCollection form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                // TODO: a delegate on OpenIdConnectAuthenticationOptions would allow for users to hook their own custom message.
                openIdConnectMessage = new OpenIdConnectMessage(form);
            }

            if (openIdConnectMessage == null)
            {
                return null;
            }

            ExceptionDispatchInfo authFailedEx = null;
            try
            {
                var messageReceivedNotification = new MessageReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };
                await Options.Notifications.MessageReceived(messageReceivedNotification);
                if (messageReceivedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (messageReceivedNotification.Skipped)
                {
                    return null;
                }

                // runtime always adds state, if we don't find it OR we failed to 'unprotect' it this is not a message we
                // should process.
                AuthenticationProperties properties = GetPropertiesFromState(openIdConnectMessage.State);
                if (properties == null)
                {
                    _logger.WriteWarning("The state field is missing or invalid.");
                    return null;
                }

                // devs will need to hook AuthenticationFailedNotification to avoid having 'raw' runtime errors displayed to users.
                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.Error))
                {
                    throw new OpenIdConnectProtocolException(
                        string.Format(CultureInfo.InvariantCulture,
                                      Resources.Exception_OpenIdConnectMessageError,
                                      openIdConnectMessage.Error, openIdConnectMessage.ErrorDescription ?? string.Empty, openIdConnectMessage.ErrorUri ?? string.Empty));
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
                }

                JwtSecurityToken jwt = null;
                ClaimsPrincipal principal = null;
                AuthenticationTicket ticket = null;
                string nonce = null;

                // Copy and augment to avoid cross request race conditions for updated configurations.
                TokenValidationParameters tvp = Options.TokenValidationParameters.Clone();

                // Hybrid or Implicit flow
                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.IdToken))
                {
                    var securityTokenReceivedNotification = new SecurityTokenReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                    {
                        ProtocolMessage = openIdConnectMessage,
                    };
                    await Options.Notifications.SecurityTokenReceived(securityTokenReceivedNotification);
                    if (securityTokenReceivedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (securityTokenReceivedNotification.Skipped)
                    {
                        return null;
                    }

                    principal = ValidateToken(openIdConnectMessage.IdToken, properties, tvp, out jwt);

                    ticket = new AuthenticationTicket(principal.Identity as ClaimsIdentity, properties);

                    if (Options.ProtocolValidator.RequireNonce)
                    {
                        if (String.IsNullOrWhiteSpace(openIdConnectMessage.Nonce))
                        {
                            openIdConnectMessage.Nonce = jwt.Payload.Nonce;
                        }

                        // deletes the nonce cookie
                        nonce = RetrieveNonce(openIdConnectMessage);
                    }

                    // remember 'session_state' and 'check_session_iframe'
                    if (!string.IsNullOrWhiteSpace(openIdConnectMessage.SessionState))
                    {
                       properties.Dictionary[OpenIdConnectSessionProperties.SessionState] = openIdConnectMessage.SessionState;
                    }

                    if (!string.IsNullOrWhiteSpace(_configuration.CheckSessionIframe))
                    {
                        properties.Dictionary[OpenIdConnectSessionProperties.CheckSessionIFrame] = _configuration.CheckSessionIframe;
                    }

                    var securityTokenValidatedNotification = new SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                    {
                        AuthenticationTicket = ticket,
                        ProtocolMessage = openIdConnectMessage,
                    };
                    await Options.Notifications.SecurityTokenValidated(securityTokenValidatedNotification);
                    if (securityTokenValidatedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (securityTokenValidatedNotification.Skipped)
                    {
                        return null;
                    }

                    // Flow possible changes
                    ticket = securityTokenValidatedNotification.AuthenticationTicket;
                }

                Options.ProtocolValidator.ValidateAuthenticationResponse(new OpenIdConnectProtocolValidationContext()
                {
                    ClientId = Options.ClientId,
                    ProtocolMessage = openIdConnectMessage,
                    ValidatedIdToken = jwt,
                    Nonce = nonce
                });

                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.Code))
                {
                    // Run AuthorizationCodeReceived notification
                    var tokenEndpointRequest = new OpenIdConnectMessage()
                    {
                        ClientId = Options.ClientId,
                        ClientSecret = Options.ClientSecret,
                        Code = openIdConnectMessage.Code,
                        GrantType = OpenIdConnectGrantTypes.AuthorizationCode,
                        RedirectUri = properties.Dictionary.ContainsKey(OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey) ?
                        properties.Dictionary[OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey] : string.Empty
                    };

                    var authorizationCodeReceivedNotification = new AuthorizationCodeReceivedNotification(Context, Options)
                    {
                        TokenEndpointRequest = tokenEndpointRequest,
                        Code = openIdConnectMessage.Code,
                        JwtSecurityToken = jwt,
                        ProtocolMessage = openIdConnectMessage,
                        RedirectUri = tokenEndpointRequest.RedirectUri,
                    };
                    await Options.Notifications.AuthorizationCodeReceived(authorizationCodeReceivedNotification);
                    if (authorizationCodeReceivedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (authorizationCodeReceivedNotification.Skipped)
                    {
                        return null;
                    }

                    tokenEndpointRequest = authorizationCodeReceivedNotification.TokenEndpointRequest;
                    openIdConnectMessage = authorizationCodeReceivedNotification.ProtocolMessage;

                    // Redeem token using the received authorization code
                    OpenIdConnectMessage tokenEndpointResponse = await RedeemAuthorizationCodeAsync(tokenEndpointRequest);

                    // Run SecurityTokenReceived notification
                    var securityTokenReceivedNotification = new SecurityTokenReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                    {
                        ProtocolMessage = tokenEndpointResponse,
                    };
                    await Options.Notifications.SecurityTokenReceived(securityTokenReceivedNotification);
                    if (securityTokenReceivedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (securityTokenReceivedNotification.Skipped)
                    {
                        return null;
                    }

                    // Validate token

                    // no need to validate signature when token is received using "code flow" as per spec
                    // [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation].
                    tvp.RequireSignedTokens = false;

                    // At least a cursory validation is required on the new IdToken, even if we've already validated the one from the authorization response.
                    // And we'll want to validate the new JWT in ValidateTokenResponse.
                    JwtSecurityToken tokenEndpointJwt = null;
                    principal = ValidateToken(tokenEndpointResponse.IdToken, properties, tvp, out tokenEndpointJwt);

                    ticket = new AuthenticationTicket(principal.Identity as ClaimsIdentity, properties);

                    nonce = tokenEndpointJwt.Payload.Nonce;
                    if (String.IsNullOrWhiteSpace(nonce))
                    {
                        nonce = ReadNonceCookie(nonce);
                    }

                    // Run SecurityTokenValidated notification
                    var securityTokenValidatedNotification = new SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                    {
                        AuthenticationTicket = ticket,
                        ProtocolMessage = tokenEndpointResponse,                        
                    };
                    await Options.Notifications.SecurityTokenValidated(securityTokenValidatedNotification);
                    if (securityTokenValidatedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (securityTokenValidatedNotification.Skipped)
                    {
                        return null;
                    }

                    // Validate the token response
                    Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext()
                    {
                        ClientId = Options.ClientId,
                        ProtocolMessage = tokenEndpointResponse,
                        ValidatedIdToken = tokenEndpointJwt,
                        Nonce = nonce
                    });

                    // Flow possible changes
                    ticket = securityTokenValidatedNotification.AuthenticationTicket;                    
                }

                return ticket;
            }
            catch (Exception exception)
            {
                // We can't await inside a catch block, capture and handle outside.
                authFailedEx = ExceptionDispatchInfo.Capture(exception);
            }

            if (authFailedEx != null)
            {
                _logger.WriteError("Exception occurred while processing message: ", authFailedEx.SourceException);

                // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the notification.
                if (Options.RefreshOnIssuerKeyNotFound && authFailedEx.SourceException.GetType().Equals(typeof(SecurityTokenSignatureKeyNotFoundException)))
                {
                    Options.ConfigurationManager.RequestRefresh();
                }

                var authenticationFailedNotification = new AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage,
                    Exception = authFailedEx.SourceException
                };
                await Options.Notifications.AuthenticationFailed(authenticationFailedNotification);
                if (authenticationFailedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (authenticationFailedNotification.Skipped)
                {
                    return null;
                }

                authFailedEx.Throw();
            }

            return null;
        }

        private ClaimsPrincipal ValidateToken(string idToken, AuthenticationProperties properties, TokenValidationParameters tvp, out JwtSecurityToken jwt)
        {
            IEnumerable<string> issuers = new[] { _configuration.Issuer };
            tvp.ValidIssuers = (tvp.ValidIssuers == null ? issuers : tvp.ValidIssuers.Concat(issuers));
            tvp.IssuerSigningKeys = (tvp.IssuerSigningKeys == null ? _configuration.SigningKeys : tvp.IssuerSigningKeys.Concat<SecurityKey>(_configuration.SigningKeys));

            SecurityToken validatedToken;
            ClaimsPrincipal principal = Options.SecurityTokenValidator.ValidateToken(idToken, tvp, out validatedToken);

            // claims principal could have changed claim values, use bits received on wire for validation.
            jwt = validatedToken as JwtSecurityToken;            

            if (Options.UseTokenLifetime)
            {
                // Override any session persistence to match the token lifetime.
                DateTime issued = jwt.ValidFrom;
                if (issued != DateTime.MinValue)
                {
                    properties.IssuedUtc = issued.ToUniversalTime();
                }
                DateTime expires = jwt.ValidTo;
                if (expires != DateTime.MinValue)
                {
                    properties.ExpiresUtc = expires.ToUniversalTime();
                }
                properties.AllowRefresh = false;
            }            

            return principal;
        }

        /// <summary>
        /// Redeems the authorization code for tokens at the token endpoint.
        /// </summary>
        /// <param name="tokenEndpointRequest">The request that will be sent to the token endpoint and is available for customization.</param>
        /// <returns>OpenIdConnect message that has tokens inside it.</returns>
        private async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync(OpenIdConnectMessage tokenEndpointRequest)
        {
            _logger.WriteVerbose("Redeem authorization code for token");

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, _configuration.TokenEndpoint);
            requestMessage.Content = new FormUrlEncodedContent(tokenEndpointRequest.Parameters);

            var responseMessage = await Backchannel.SendAsync(requestMessage);

            var contentType = responseMessage.Content.Headers.ContentType;
            var contentMediaType = contentType == null ? null : contentType.MediaType;
            if (string.IsNullOrEmpty(contentMediaType))
            {
                _logger.WriteVerbose(string.Format("Unexpected token response format. Status Code: {0}. Content-Type header is missing.", (int)responseMessage.StatusCode));
            }
            else if (!string.Equals(contentMediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                _logger.WriteVerbose(string.Format("Unexpected token response format. Status Code: {0}. Content-Type {responseMessage.Content.Headers.ContentType}.", (int)responseMessage.StatusCode));
            }

            // Error handling:
            // 1. If the response body can't be parsed as json, throws.
            // 2. If the response's status code is not in 2XX range, throw OpenIdConnectProtocolException. If the body is correct parsed,
            //    pass the error information from body to the exception.
            OpenIdConnectMessage message;
            try
            {
                var responseContent = await responseMessage.Content.ReadAsStringAsync();
                message = new OpenIdConnectMessage(responseContent);
            }
            catch (Exception ex)
            {
                throw new OpenIdConnectProtocolException(
                    string.Format("Failed to parse token response body as JSON. Status Code: {0}. Content-Type: {1}", (int)responseMessage.StatusCode, responseMessage.Content.Headers.ContentType),
                    ex);
            }

            if (!responseMessage.IsSuccessStatusCode)
            {
                throw new OpenIdConnectProtocolException(
                        string.Format(CultureInfo.InvariantCulture,
                                      Resources.Exception_OpenIdConnectMessageError,
                                      message.Error, message.ErrorDescription ?? string.Empty, message.ErrorUri ?? string.Empty));
            }

            return message;
        }

        /// <summary>
        /// Sets <see cref="OpenIdConnectMessage.Nonce"/> to <see cref="Options.ProtocolValidator.GenerateNonce"/>.
        /// </summary>
        /// <param name="message">the <see cref="OpenIdConnectMessage"/> being processed.</param>
        /// <remarks>Calls <see cref="RememberNonce"/> to add the nonce to a protected cookie. 
        protected virtual void AddNonceToMessage(OpenIdConnectMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            string nonce = Options.ProtocolValidator.GenerateNonce();
            message.Nonce = nonce;
            RememberNonce(message, nonce);
        }

        /// <summary>
        /// 'Remembers' the nonce associated with this message. By default the nonce added as a secure cookie.
        /// </summary>
        /// <param name="message"><see cref="OpenIdConnectMessage"/> associated with the nonce.</param>
        /// <param name="nonce">the nonce to remember.</param>
        /// <remarks>A cookie is added with the name obtained from  <see cref="GetNonceKey"/>.</remarks>
        protected virtual void RememberNonce(OpenIdConnectMessage message, string nonce)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (nonce == null)
            {
                throw new ArgumentNullException("nonce");
            }

            AuthenticationProperties properties = new AuthenticationProperties();
            properties.Dictionary.Add(NonceProperty, nonce);
            Options.CookieManager.AppendResponseCookie(
                Context,
                GetNonceKey(nonce),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsSecure,
                    Expires = DateTime.UtcNow + Options.ProtocolValidator.NonceLifetime
                });
        }

        /// <summary>
        /// Retrieves the 'nonce' for a message.
        /// </summary>
        /// <param name="message">the <see cref="OpenIdConnectMessage"/> being processed.</param>
        /// <returns>the nonce associated with this message if found, null otherwise.</returns>
        /// <remarks>Looks for a cookie named: 'OpenIdConnectAuthenticationDefaults.CookiePrefix + OpenIdConnectAuthenticationDefaults.Nonce + Options.AuthenticationType' in the Resquest.</para></remarks>
        protected virtual string RetrieveNonce(OpenIdConnectMessage message)
        {
            if (message == null)
            {
                return null;
            }

            string nonceKey = GetNonceKey(message.Nonce);
            if (nonceKey == null)
            {
                return null;
            }

            return ReadNonceCookie(nonceKey);
        }

        protected virtual string ReadNonceCookie(string nonceKey)
        {
            string nonceCookie = Options.CookieManager.GetRequestCookie(Context, nonceKey);
            if (nonceCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsSecure
                };

                Options.CookieManager.DeleteCookie(Context, nonceKey, cookieOptions);
            }

            if (string.IsNullOrWhiteSpace(nonceCookie))
            {
                _logger.WriteWarning(Resources.Warning_NonceCookieNotFound);
                return null;
            }

            string nonce = null;
            AuthenticationProperties nonceProperties = Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(nonceCookie)));
            if (nonceProperties != null)
            {
                nonceProperties.Dictionary.TryGetValue(NonceProperty, out nonce);
            }
            else
            {
                _logger.WriteWarning(Resources.Warning_NonceCookieUnprotectFailure);
            }

            return nonce;
        }

        /// <summary>
        /// Builds a key from the nonce and constants.
        /// </summary>
        /// <param name="nonce">value generated by the runtime</param>
        /// <remarks>'OpenIdConnectAuthenticationDefaults.CookiePrefix + OpenIdConnectAuthenticationDefaults.Nonce + Options.AuthenticationType' is attached to the Response.</para></remarks>
        /// <returns></returns>
        protected virtual string GetNonceKey(string nonce)
        {
            if (nonce == null)
            {
                return null;
            }

            using (HashAlgorithm hash = SHA256.Create())
            {
                // computing the hash of the nonce and appending it to the cookie name
                // it is possible here that the value is NOT an int64, but this had to be because a custom nonce was created.
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + OpenIdConnectAuthenticationDefaults.Nonce + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(nonce)));
            }
        }
 
        private AuthenticationProperties GetPropertiesFromState(string state)
        {
            // assume a well formed query string: <a=b&>OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey=kasjd;fljasldkjflksdj<&c=d>
            int startIndex = 0;
            if (string.IsNullOrWhiteSpace(state) || (startIndex = state.IndexOf(OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey, StringComparison.Ordinal)) == -1)
            {
                return null;
            }

            int authenticationIndex = startIndex + OpenIdConnectAuthenticationDefaults.AuthenticationPropertiesKey.Length;
            if (authenticationIndex == -1 || authenticationIndex == state.Length || state[authenticationIndex] != '=')
            {
                return null;
            }

            // scan rest of string looking for '&'
            authenticationIndex++;
            int endIndex = state.Substring(authenticationIndex, state.Length - authenticationIndex).IndexOf("&", StringComparison.Ordinal);

            // -1 => no other parameters are after the AuthenticationPropertiesKey
            if (endIndex == -1)
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex).Replace('+', ' ')));
            }
            else
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex, endIndex).Replace('+', ' ')));
            }
        }

        /// <summary>
        /// Calls InvokeReplyPathAsync
        /// </summary>
        /// <returns>True if the request was handled, false if the next middleware should be invoked.</returns>
        public override Task<bool> InvokeAsync()
        {
            return InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            AuthenticationTicket ticket = await AuthenticateAsync();

            if (ticket != null)
            {
                string value;
                if (ticket.Properties.Dictionary.TryGetValue(HandledResponse, out value) && value == "true")
                {
                    return true;
                }
                if (ticket.Identity != null)
                {
                    Request.Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                }
                // Redirect back to the original secured resource, if any.
                if (!string.IsNullOrWhiteSpace(ticket.Properties.RedirectUri))
                {
                    Response.Redirect(ticket.Properties.RedirectUri);
                    return true;
                }
            }

            return false;
        }

        private static AuthenticationTicket GetHandledResponseTicket()
        {
            return new AuthenticationTicket(null, new AuthenticationProperties(new Dictionary<string, string>() { { HandledResponse, "true" } }));
        }
    }
}
