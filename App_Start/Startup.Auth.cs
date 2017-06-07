using System;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.WsFederation;
using Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace KatanaSample
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            //ILogger logger = app.CreateLogger<Startup>();
            //logger.WriteError("App is starting up");
            //logger.WriteCritical("App is starting up");
            //logger.WriteWarning("App is starting up");
            //logger.WriteVerbose("App is starting up");
            //logger.WriteInformation("App is starting up");

            string authority = "https://login.microsoftonline.com/sijun.onmicrosoft.com/";
            string clientAddress = "http://localhost:42023/";
            string clientId = "e3b475b5-2f59-4a71-86e9-821b9f533cd3";
            string oidcMetadataAddress = authority + ".well-known/openid-configuration";
            string wsFedMetadataAddress = "https://login.microsoftonline.com/268da1a1-9db4-48b9-b1fe-683250ba90cc/federationmetadata/2007-06/federationmetadata.xml";

            ServicePointManager.ServerCertificateValidationCallback = ValidateServerCert;
            app.SetDefaultSignInAsAuthenticationType(OpenIdConnectAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions { AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType });
            var openIdConnectAuthenticationOptions = new OpenIdConnectAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                Authority = authority,
                BackchannelCertificateValidator = new CustomCertifiateValidator(),
                ClientId = clientId,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = (notification) => { return Task.FromResult<object>(null); },
                    AuthenticationFailed = (notification) => 
                    {
                        return Task.FromResult<object>(null);
                    },
                    MessageReceived = (notification) => 
                    {
                        return Task.FromResult<object>(null);
                    },
                    RedirectToIdentityProvider = (notification) => {
                        return Task.FromResult(0);
                    },
                    SecurityTokenReceived  = (notification) => 
                    {
                        return Task.FromResult<object>(null);
                    },
                    SecurityTokenValidated = (notification) => 
                    {
                        return Task.FromResult<object>(null);
                    },
                },
                PostLogoutRedirectUri = string.Format(CultureInfo.InvariantCulture, "{0}Account/SignedOut", clientAddress),
                RedirectUri = clientAddress,
                ResponseType = OpenIdConnectResponseType.IdToken,
            };

            var handler = openIdConnectAuthenticationOptions.SecurityTokenValidator as JwtSecurityTokenHandler;
            if (handler != null)
            {
                handler.InboundClaimTypeMap.Clear();
                handler.InboundClaimFilter.Add("nonce");
                handler.InboundClaimFilter.Add("iat");
                handler.InboundClaimFilter.Add("exp");
                handler.InboundClaimFilter.Add("nbf");
            }
            
            app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);
            var wsFedOptions = new WsFederationAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType,
                Notifications = new WsFederationAuthenticationNotifications
                {
                    MessageReceived = (notification) =>
                    {
                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = (notification) => {
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = (notification) =>
                    {
                        return Task.FromResult<object>(null);
                    }
                },
                TokenValidationParameters = new TokenValidationParameters
                {
                    AudienceValidator = (audiences, securityToken, validationParameters) => { return true; },
                    IssuerValidator = (issuer, securitytoken, validationParameters) => { return issuer; },
                    SaveSigninToken = true,
                },
                MetadataAddress = wsFedMetadataAddress,
                Wreply = clientAddress,
                Wtrealm = clientId                
            };

            app.UseWsFederationAuthentication(wsFedOptions);
        }

        internal static bool ValidateServerCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
          return true;
        }
    }

    class CustomCertifiateValidator : ICertificateValidator
    {
        public bool Validate(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }

    class AuthenticationPropertiesFormater : ISecureDataFormat<AuthenticationProperties>
    {
        public AuthenticationPropertiesFormater()
        {

        }

        public string Protect(AuthenticationProperties data)
        {
            StringBuilder sb = new StringBuilder();
            foreach( var key in data.Dictionary)
            {
                sb.Append(key.Key);
                sb.Append(":");
                sb.Append(key.Value);
            }

            return sb.ToString();
        }

        public AuthenticationProperties Unprotect(string protectedText)
        {
            return new AuthenticationProperties();
        }
    }

    public class StringSerializer : IDataSerializer<string>
    {
        public string Deserialize(byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }

        public byte[] Serialize(string model)
        {
            return Encoding.UTF8.GetBytes(model);
        }
    }

}