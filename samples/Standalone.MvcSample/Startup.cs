using System.IO;
using System.Security.Cryptography.X509Certificates;
using ActiveLogin.Authentication.BankId.AspNetCore;
using ActiveLogin.Authentication.BankId.AspNetCore.Azure;
using ActiveLogin.Authentication.GrandId.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Azure.KeyVault;
using System;
using System.Globalization;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using System.Collections.Generic;

namespace Standalone.MvcSample
{
    public class Startup
    {
        private readonly IHostingEnvironment _environment;

        public Startup(IConfiguration configuration, IHostingEnvironment environment)
        {
            _environment = environment;
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie()
                .AddBankId(builder =>
                {
                    builder.AddSameDevice(BankIdAuthenticationDefaults.SameDeviceAuthenticationScheme, "BankID (SameDevice)", options => { })
                           .AddOtherDevice(BankIdAuthenticationDefaults.OtherDeviceAuthenticationScheme, "BankID (OtherDevice)", options => { });

                    builder.Configure(options =>
                    {
                        options.IssueBirthdateClaim = true;
                        options.IssueGenderClaim = true;
                    });

                    if (Configuration.GetValue("ActiveLogin:BankId:UseSimulatedEnvironment", false))
                    {
                        builder.UseSimulatedEnvironment();
                    }
                    else
                    {
                        if (Configuration.GetValue("ActiveLogin:BankId:UseTestEnvironment", false))
                            builder.UseTestEnvironment();
                        else
                            builder.UseProductionEnvironment();

                        builder.UseRootCaCertificate(Path.Combine(_environment.ContentRootPath, Configuration.GetValue<string>("ActiveLogin:BankId:CaCertificate:FilePath")));

                        if (Configuration.GetValue("ActiveLogin:BankId:ClientCertificate:UseAzureKeyVault", false))
                            builder.UseClientCertificateFromAzureKeyVault(Configuration.GetSection("ActiveLogin:BankId:ClientCertificate:AzureKeyVault"));
                        else
                            builder.UseClientCertificate(() => GetCertificateFromStore(Configuration.GetValue<string>("ActiveLogin:BankId:ClientCertificate:Local:FileName")));
                    }
                });

            var supportedCultures = new[]
            {
                new CultureInfo("en-US"),
                new CultureInfo("en"),
                new CultureInfo("sv-SE"),
                new CultureInfo("sv")
            };

            services.Configure<RequestLocalizationOptions>(options =>
            {
                options.DefaultRequestCulture = new RequestCulture("sv");
                options.SupportedCultures = supportedCultures;
                options.SupportedUICultures = supportedCultures;
                options.RequestCultureProviders = new List<IRequestCultureProvider>
                {
                    new QueryStringRequestCultureProvider(),
                    new CookieRequestCultureProvider()
                };
            });

            services.AddMvc(config =>
            {
                config.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            })
            .SetCompatibilityVersion(CompatibilityVersion.Version_2_2)
            .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
            .AddDataAnnotationsLocalization();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseDeveloperExceptionPage();

            app.UseRequestLocalization();

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // obtained & slightly modified from https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=netframework-4.7.2
        private static X509Certificate2 GetCertificateFromStore(string certName)
        {
            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                if (signingCert.Count == 0)
                {
                    signingCert = currentCerts.Find(X509FindType.FindBySubjectName, certName, false);
                    if (signingCert.Count == 0)
                        return null;
                }
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}
