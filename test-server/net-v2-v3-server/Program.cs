using NetV2V3Server.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<IClientCacheService, ClientCacheService>();

#if S3EC_V2
const int port = 8083;
#else
const int port = 8084;
#endif

builder.WebHost.UseUrls($"http://localhost:{port}");

var app = builder.Build();

app.MapControllers();

Console.WriteLine($"Starting server on port {port}");
app.Run();
