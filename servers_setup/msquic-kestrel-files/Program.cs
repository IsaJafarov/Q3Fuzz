var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args=args , WebRootPath = "/usr/local/nginx/html" });

builder.WebHost.ConfigureKestrel((context, options) =>
{
    options.ListenAnyIP(443, listenOptions =>
    {
        listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http3;
        listenOptions.UseHttps( "../certs/prett3.com.pfx");
    });
});

var app = builder.Build();
app.UseStaticFiles();
app.Run();
