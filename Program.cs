/**
 * C# Flux Starter - Backend Server
 *
 * A WebSocket proxy server that transparently forwards audio and transcription
 * messages between browser clients and Deepgram's Flux API (next-gen streaming
 * transcription with turn detection).
 *
 * Key Features:
 * - WebSocket proxy: /api/flux -> wss://api.deepgram.com/v2/listen
 * - Bidirectional message forwarding (binary audio + JSON results)
 * - JWT session auth with rate limiting (production only)
 * - Metadata endpoint: GET /api/metadata
 * - CORS enabled for frontend communication
 * - Graceful shutdown with connection tracking
 */

using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Deepgram;
using Deepgram.Models.Flux.WebSocket;
using Microsoft.IdentityModel.Tokens;
using Tomlyn;
using Tomlyn.Model;
using HttpResults = Microsoft.AspNetCore.Http.Results;

// ============================================================================
// ENVIRONMENT LOADING
// ============================================================================

DotNetEnv.Env.Load();

// ============================================================================
// CONFIGURATION
// ============================================================================

var port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var p) ? p : 8081;
var host = Environment.GetEnvironmentVariable("HOST") ?? "0.0.0.0";
var frontendPort = int.TryParse(Environment.GetEnvironmentVariable("FRONTEND_PORT"), out var fp) ? fp : 8080;

// ============================================================================
// SESSION AUTH - JWT tokens with rate limiting for production security
// ============================================================================

var sessionSecretEnv = Environment.GetEnvironmentVariable("SESSION_SECRET");
var sessionSecret = sessionSecretEnv ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
var sessionSecretKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(sessionSecret));

const int JwtExpirySeconds = 3600; // 1 hour

string CreateSessionToken()
{
    var handler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor
    {
        Expires = DateTime.UtcNow.AddSeconds(JwtExpirySeconds),
        SigningCredentials = new SigningCredentials(sessionSecretKey, SecurityAlgorithms.HmacSha256Signature),
    };
    var token = handler.CreateToken(descriptor);
    return handler.WriteToken(token);
}

bool ValidateSessionToken(string token)
{
    try
    {
        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = sessionSecretKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero,
        }, out _);
        return true;
    }
    catch
    {
        return false;
    }
}

/// Validates JWT from WebSocket subprotocol: access_token.<jwt>
string? ValidateWsToken(string? protocolHeader)
{
    if (string.IsNullOrEmpty(protocolHeader)) return null;
    var protocols = protocolHeader.Split(',', StringSplitOptions.TrimEntries);
    var tokenProto = protocols.FirstOrDefault(p => p.StartsWith("access_token."));
    if (tokenProto == null) return null;
    var token = tokenProto["access_token.".Length..];
    return ValidateSessionToken(token) ? tokenProto : null;
}

// ============================================================================
// API KEY LOADING
// ============================================================================

static string LoadApiKey()
{
    var apiKey = Environment.GetEnvironmentVariable("DEEPGRAM_API_KEY");

    if (string.IsNullOrEmpty(apiKey))
    {
        Console.Error.WriteLine("\n❌ ERROR: Deepgram API key not found!\n");
        Console.Error.WriteLine("Please set your API key using one of these methods:\n");
        Console.Error.WriteLine("1. Create a .env file (recommended):");
        Console.Error.WriteLine("   DEEPGRAM_API_KEY=your_api_key_here\n");
        Console.Error.WriteLine("2. Environment variable:");
        Console.Error.WriteLine("   export DEEPGRAM_API_KEY=your_api_key_here\n");
        Console.Error.WriteLine("Get your API key at: https://console.deepgram.com\n");
        Environment.Exit(1);
    }

    return apiKey;
}

var apiKey = LoadApiKey();

// Initialize the Deepgram library once at startup.
Library.Initialize();

// ============================================================================
// SETUP
// ============================================================================

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://{host}:{port}");

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(
                $"http://localhost:{frontendPort}",
                $"http://127.0.0.1:{frontendPort}")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

var app = builder.Build();
app.UseCors();
app.UseWebSockets();

// Track active connections for graceful shutdown
var activeConnections = new ConcurrentDictionary<string, WebSocket>();

// ============================================================================
// SESSION ROUTES - Auth endpoints (unprotected)
// ============================================================================

/// GET /api/session — Issues a JWT for API authentication
app.MapGet("/api/session", () =>
{
    var token = CreateSessionToken();
    return HttpResults.Json(new Dictionary<string, string> { ["token"] = token });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Builds a Deepgram FluxSchema from the query parameters forwarded by the client.
/// These are the same parameters the raw proxy previously appended to the Deepgram URL.
/// NOTE: The Flux WebSocket client is a PREVIEW feature of the Deepgram .NET SDK — its
/// API surface may change in future releases.
static FluxSchema BuildFluxSchema(string? queryString)
{
    var query = System.Web.HttpUtility.ParseQueryString(queryString ?? "");

    // Flux uses a hardcoded model and minimal required parameters.
    var schema = new FluxSchema
    {
        Model = "flux-general-en",
        Encoding = query["encoding"] ?? "linear16",
        SampleRate = int.TryParse(query["sample_rate"], out var sr) ? sr : 16000,
    };

    // Optional flux-specific parameters (only set if provided).
    if (double.TryParse(query["eot_threshold"], out var eot))
        schema.EotThreshold = eot;
    if (double.TryParse(query["eager_eot_threshold"], out var eager))
        schema.EagerEotThreshold = eager;
    if (int.TryParse(query["eot_timeout_ms"], out var timeout))
        schema.EotTimeoutMs = timeout;

    // keyterm is a multi-value parameter.
    var keyterms = query.GetValues("keyterm");
    if (keyterms is { Length: > 0 })
        schema.Keyterm = keyterms.ToList();

    return schema;
}

/// Handles a single session between a browser client and Deepgram Flux.
///
/// The browser-facing WebSocket is unchanged: the client still streams binary
/// linear16 audio and receives Flux's native JSON messages ("Connected",
/// "TurnInfo", "Error"). Only the Deepgram-facing side now uses the Deepgram .NET
/// SDK (ClientFactory.CreateFluxWebSocketClient) instead of a raw ClientWebSocket.
/// The SDK's typed response records serialize back to Flux's wire format via
/// ToString(), so the frontend needs no changes.
///
/// PREVIEW: the Flux client is a preview feature of the SDK; its shape may change.
async Task HandleFluxStream(WebSocket clientWs, string? queryString, string apiKey, CancellationToken appCt)
{
    var connectionId = Guid.NewGuid().ToString("N")[..8];
    activeConnections[connectionId] = clientWs;
    Console.WriteLine($"[{connectionId}] Client connected to /api/flux");

    // Outbound queue → browser. SDK event handlers fire from the receive loop and may
    // overlap, so all sends to the client WebSocket are funneled through one writer.
    var outbound = System.Threading.Channels.Channel.CreateUnbounded<string>();

    // Deepgram Flux client (replaces the raw ClientWebSocket).
    var fluxClient = ClientFactory.CreateFluxWebSocketClient(apiKey);

    // Forward each Flux event to the browser as the raw JSON the frontend expects.
    await fluxClient.Subscribe(new EventHandler<ConnectedResponse>((_, e) => outbound.Writer.TryWrite(e.ToString())));
    await fluxClient.Subscribe(new EventHandler<TurnInfoResponse>((_, e) => outbound.Writer.TryWrite(e.ToString())));
    await fluxClient.Subscribe(new EventHandler<ErrorResponse>((_, e) => outbound.Writer.TryWrite(e.ToString())));

    // Pump queued messages to the browser one at a time.
    var pump = Task.Run(async () =>
    {
        try
        {
            await foreach (var msg in outbound.Reader.ReadAllAsync(appCt))
            {
                if (clientWs.State != WebSocketState.Open) break;
                await clientWs.SendAsync(Encoding.UTF8.GetBytes(msg), WebSocketMessageType.Text, true, appCt);
            }
        }
        catch (OperationCanceledException) { }
        catch (WebSocketException) { }
    });

    try
    {
        var schema = BuildFluxSchema(queryString);
        Console.WriteLine($"[{connectionId}] Connecting to Deepgram Flux API...");

        if (!await fluxClient.Connect(schema))
        {
            Console.Error.WriteLine($"[{connectionId}] Failed to connect to Deepgram Flux");
            if (clientWs.State == WebSocketState.Open)
            {
                await clientWs.CloseAsync(
                    WebSocketCloseStatus.InternalServerError,
                    "Deepgram connection error",
                    CancellationToken.None);
            }
            return;
        }
        Console.WriteLine($"[{connectionId}] ✓ Connected to Deepgram Flux API");

        // Forward the browser's audio into Flux until the client disconnects. The
        // frontend sends a {"type":"CloseStream"} text frame for graceful shutdown;
        // fluxClient.Stop() (in finally) sends the CloseStream control message to Flux.
        var buffer = new byte[8192];
        while (clientWs.State == WebSocketState.Open)
        {
            var result = await clientWs.ReceiveAsync(new ArraySegment<byte>(buffer), appCt);
            if (result.MessageType == WebSocketMessageType.Close) break;

            if (result.MessageType == WebSocketMessageType.Binary && result.Count > 0)
            {
                var chunk = new byte[result.Count];
                Array.Copy(buffer, chunk, result.Count);
                fluxClient.Send(chunk);
            }
            else if (result.MessageType == WebSocketMessageType.Text)
            {
                // The only control message the frontend sends is CloseStream → stop.
                var text = Encoding.UTF8.GetString(buffer, 0, result.Count);
                if (text.Contains("CloseStream")) break;
            }
        }
    }
    catch (OperationCanceledException)
    {
        // App shutdown or client disconnect
    }
    catch (WebSocketException ex)
    {
        Console.Error.WriteLine($"[{connectionId}] WebSocket error: {ex.Message}");
    }
    finally
    {
        try { await fluxClient.Stop(); } catch { }
        outbound.Writer.TryComplete();
        try { await pump; } catch { }

        if (clientWs.State == WebSocketState.Open)
        {
            try
            {
                await clientWs.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "Connection ended",
                    CancellationToken.None);
            }
            catch { }
        }

        activeConnections.TryRemove(connectionId, out _);
        Console.WriteLine($"[{connectionId}] Connection closed ({activeConnections.Count} active)");
    }
}

// ============================================================================
// WEBSOCKET ENDPOINT
// ============================================================================

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/api/flux" && context.WebSockets.IsWebSocketRequest)
    {
        // Validate JWT from WebSocket subprotocol
        var protocolHeader = context.Request.Headers["Sec-WebSocket-Protocol"].FirstOrDefault();
        var validProto = ValidateWsToken(protocolHeader);
        if (validProto == null)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var clientWs = await context.WebSockets.AcceptWebSocketAsync(validProto);
        await HandleFluxStream(clientWs, context.Request.QueryString.Value, apiKey, context.RequestAborted);
    }
    else
    {
        await next(context);
    }
});

// ============================================================================
// API ROUTES
// ============================================================================

// Health check endpoint
app.MapGet("/health", () => HttpResults.Json(new { status = "ok", service = "flux" }));

/// GET /api/metadata
///
/// Returns metadata about this starter application from deepgram.toml
app.MapGet("/api/metadata", () =>
{
    try
    {
        var tomlPath = Path.Combine(Directory.GetCurrentDirectory(), "deepgram.toml");
        var tomlContent = File.ReadAllText(tomlPath);
        var tomlModel = Toml.ToModel(tomlContent);

        if (!tomlModel.ContainsKey("meta") || tomlModel["meta"] is not TomlTable metaTable)
        {
            return HttpResults.Json(new Dictionary<string, string>
            {
                ["error"] = "INTERNAL_SERVER_ERROR",
                ["message"] = "Missing [meta] section in deepgram.toml",
            }, statusCode: 500);
        }

        var meta = new Dictionary<string, object?>();
        foreach (var kvp in metaTable)
        {
            meta[kvp.Key] = kvp.Value;
        }

        return HttpResults.Json(meta);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error reading metadata: {ex}");
        return HttpResults.Json(new Dictionary<string, string>
        {
            ["error"] = "INTERNAL_SERVER_ERROR",
            ["message"] = "Failed to read metadata from deepgram.toml",
        }, statusCode: 500);
    }
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    Console.WriteLine($"\nShutting down... Closing {activeConnections.Count} active connection(s)...");
    foreach (var kvp in activeConnections)
    {
        try
        {
            if (kvp.Value.State == WebSocketState.Open)
            {
                kvp.Value.CloseAsync(
                    WebSocketCloseStatus.EndpointUnavailable,
                    "Server shutting down",
                    CancellationToken.None).Wait(TimeSpan.FromSeconds(5));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error closing connection {kvp.Key}: {ex.Message}");
        }
    }
    Console.WriteLine("All connections closed.");
});

// ============================================================================
// SERVER START
// ============================================================================

Console.WriteLine();
Console.WriteLine(new string('=', 70));
Console.WriteLine($"🚀 Backend API Server running at http://localhost:{port}");
Console.WriteLine($"📡 CORS enabled for http://localhost:{frontendPort}");
Console.WriteLine($"📡 GET  /api/session");
Console.WriteLine($"📡 WebSocket endpoint: ws://localhost:{port}/api/flux (auth required)");
Console.WriteLine($"📡 GET  /health");
Console.WriteLine($"📡 GET  /api/metadata");
Console.WriteLine($"\n💡 Frontend should be running on http://localhost:{frontendPort}");
Console.WriteLine(new string('=', 70));
Console.WriteLine();

app.Run();
