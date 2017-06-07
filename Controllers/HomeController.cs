using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.WsFederation;

namespace KatanaSample.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
                ViewBag.ClaimsPrincipal = User as ClaimsPrincipal;

            return View();
        }

        public void SignOut()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.Identity.AuthenticationType == OpenIdConnectAuthenticationDefaults.AuthenticationType)
                    HttpContext.GetOwinContext().Authentication.SignOut(new string[] { CookieAuthenticationDefaults.AuthenticationType, OpenIdConnectAuthenticationDefaults.AuthenticationType });
                else if (User.Identity.AuthenticationType == WsFederationAuthenticationDefaults.AuthenticationType)
                    HttpContext.GetOwinContext().Authentication.SignOut(new string[] { CookieAuthenticationDefaults.AuthenticationType, WsFederationAuthenticationDefaults.AuthenticationType });
            }
        }

        public void SignInOIDC()
        {
            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        public void SignInWsFed()
        {
            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" }, WsFederationAuthenticationDefaults.AuthenticationType);
        }

        public ActionResult SignedOut()
        {
            SignOut();
            return View();
        }
    }
}