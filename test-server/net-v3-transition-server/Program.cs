using NetV2V3Server.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSingleton<IClientCacheService, ClientCacheService>();

const int port = 8100;

builder.WebHost.UseUrls($"http://localhost:{port}");

var app = builder.Build();

app.MapControllers();

Console.WriteLine($"Starting server on port {port}");
app.Run();
