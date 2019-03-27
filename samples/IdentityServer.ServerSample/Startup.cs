using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ActiveLogin.Authentication.BankId.AspNetCore;
using ActiveLogin.Authentication.BankId.AspNetCore.Azure;
using ActiveLogin.Authentication.GrandId.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.ApplicationInsights;

namespace IdentityServer.ServerSample
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
            services.AddLogging(loggingBuilder =>
            {
                ApplicationInsightsLoggingBuilderExtensions.AddApplicationInsights(loggingBuilder);
            });

            services
                .AddApplicationInsightsTelemetry(Configuration)
                .AddOptions<ApplicationInsightsLoggerOptions>();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.None;
                options.HttpOnly = HttpOnlyPolicy.Always;
                options.Secure = CookieSecurePolicy.Always;
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
            });

            services.AddIdentityServer(x => { x.Authentication.CookieLifetime = TimeSpan.FromHours(1); })
                    .AddDeveloperSigningCredential()
                    .AddInMemoryIdentityResources(Config.GetIdentityResources())
                    .AddInMemoryClients(Config.GetClients(Configuration.GetSection("ActiveLogin:Clients")));

            // Sample of using BankID with in memory dev environment
            //services.AddAuthentication()
            //        .AddBankId(builder =>
            //    {
            //        builder
            //            .UseSimulatedEnvironment()
            //            .AddSameDevice()
            //            .AddOtherDevice();
            //    });

            // Sample of using BankID with production environment
            //services.AddAuthentication()
            //        .AddBankId(builder =>
            //        {
            //            builder
            //                .UseProductionEnvironment()
            //                .UseClientCertificateFromAzureKeyVault(Configuration.GetSection("ActiveLogin:BankId:ClientCertificate"))
            //                .UseRootCaCertificate(Path.Combine(_environment.ContentRootPath, Configuration.GetValue<string>("ActiveLogin:BankId:CaCertificate:FilePath")))
            //                .AddSameDevice()
            //                .AddOtherDevice();
            //        });


            // Sample of using BankID through GrandID (Svensk E-identitet) with in memory dev environment
            //services.AddAuthentication()
            //        .AddGrandId(builder =>
            //        {
            //            builder
            //                .UseSimulatedEnvironment()
            //                .AddBankIdSameDevice(options => { })
            //                .AddBankIdOtherDevice(options => { });
            //        });

            // Sample of using BankID through GrandID (Svensk E-identitet) with production environment
            //services.AddAuthentication()
            //        .AddGrandId(builder =>
            //        {
            //            builder
            //                .UseProductionEnvironment(config =>
            //                {
            //                    config.ApiKey = Configuration.GetValue<string>("ActiveLogin:GrandId:ApiKey");
            //                    config.BankIdServiceKey = Configuration.GetValue<string>("ActiveLogin:GrandId:BankIdServiceKey");
            //                })
            //                .AddBankIdChooseDevice();
            //        });

            // Full sample with both BankID and GrandID with custom display name and multiple environment support
            services.AddAuthentication()
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
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseHttpsRedirection();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseIdentityServer();

            app.UseRequestLocalization();

            app.UseMvcWithDefaultRoute();
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
