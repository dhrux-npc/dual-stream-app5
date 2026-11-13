using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);
var railwayPublicDomain = builder.Configuration["RAILWAY_PUBLIC_DOMAIN"];
if (string.IsNullOrWhiteSpace(builder.Configuration["PUBLIC_ORIGIN"]) &&
    !string.IsNullOrWhiteSpace(railwayPublicDomain))
{
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["PUBLIC_ORIGIN"] = $"https://{railwayPublicDomain}"
    });
}
builder.Services.AddSingleton<RoomHub>();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedProto |
        ForwardedHeaders.XForwardedHost;
    options.ForwardLimit = 1;
    var trustedProxyIps = builder.Configuration["TRUSTED_PROXY_IPS"];
    if (!string.IsNullOrWhiteSpace(trustedProxyIps))
    {
        foreach (var address in trustedProxyIps.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!System.Net.IPAddress.TryParse(address, out var proxyIp))
            {
                throw new InvalidOperationException("TRUSTED_PROXY_IPS must contain only comma-separated IP addresses.");
            }
            options.KnownProxies.Add(proxyIp);
        }
    }
});
var configuredTurnUrls = builder.Configuration["TURN_URL"]?
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];
var turnSharedSecret = builder.Configuration["TURN_SHARED_SECRET"];
if (configuredTurnUrls.Length > 0 &&
    (string.IsNullOrWhiteSpace(turnSharedSecret) || turnSharedSecret.Length < 32))
{
    throw new InvalidOperationException("TURN_URL requires a TURN_SHARED_SECRET of at least 32 characters.");
}
if (configuredTurnUrls.Any(url =>
        !url.StartsWith("turn:", StringComparison.OrdinalIgnoreCase) &&
        !url.StartsWith("turns:", StringComparison.OrdinalIgnoreCase)))
{
    throw new InvalidOperationException("TURN_URL must contain only turn: or turns: URLs.");
}

var configuredPublicOrigin = builder.Configuration["PUBLIC_ORIGIN"];
if (!string.IsNullOrWhiteSpace(configuredPublicOrigin) &&
    (!Uri.TryCreate(configuredPublicOrigin, UriKind.Absolute, out var publicOrigin) ||
     publicOrigin.Scheme is not ("http" or "https") ||
     publicOrigin.AbsolutePath != "/" ||
     !string.IsNullOrEmpty(publicOrigin.Query) ||
     !string.IsNullOrEmpty(publicOrigin.Fragment)))
{
    throw new InvalidOperationException("PUBLIC_ORIGIN must be an origin such as https://stream.example.com, with no path or query.");
}

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        _ => RateLimitPartition.GetConcurrencyLimiter(
            "all-requests",
            _ => new ConcurrencyLimiterOptions
            {
                PermitLimit = 512,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
    options.AddPolicy("signal", context =>
        RateLimitPartition.GetConcurrencyLimiter(
            GetRateLimitPartitionKey(context),
            _ => new ConcurrencyLimiterOptions
            {
                PermitLimit = 8,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));
});

var app = builder.Build();
app.UseForwardedHeaders();
app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = TimeSpan.FromSeconds(30)
});
app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), display-capture=(self)";
    context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
    if (Uri.TryCreate(app.Configuration["PUBLIC_ORIGIN"], UriKind.Absolute, out var publicOriginUri) &&
        publicOriginUri.Scheme == Uri.UriSchemeHttps)
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";
    }
    context.Response.Headers.ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "font-src 'self' data:; " +
        "connect-src 'self' ws: wss:; " +
        "img-src 'self' data:; " +
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = context =>
        context.Context.Response.Headers.CacheControl = "no-cache, must-revalidate"
});
app.UseRouting();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.Map("/signal", HandleSignalAsync).RequireRateLimiting("signal");

app.Run();

static async Task HandleSignalAsync(HttpContext context)
{
    if (!IsSameOrigin(context))
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return;
    }

    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    using var socket = await context.WebSockets.AcceptWebSocketAsync();
    var hub = context.RequestServices.GetRequiredService<RoomHub>();
    RoomHub.Client? client = null;
    string? requestType = null;

    try
    {
        var firstMessage = await ReceiveMessageAsync(socket, context.RequestAborted);
        if (firstMessage is null)
        {
            await CloseSocketAsync(socket, WebSocketCloseStatus.PolicyViolation, "Missing room request");
            return;
        }

        using (var document = JsonDocument.Parse(firstMessage))
        {
            var root = document.RootElement;
            var type = ReadString(root, "type");
            requestType = type;
            var roomId = ReadString(root, "room")?.Trim().ToLowerInvariant();
            var password = ReadString(root, "password") ?? string.Empty;
            if (roomId is null ||
                roomId.Length is < 3 or > 48 ||
                roomId.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_') ||
                type is not ("create" or "join" or "resume") ||
                (type is "join" or "resume") && !IsValidInviteKey(password))
            {
                await SendJsonAsync(socket, new { type = "error", message = "Enter a valid room ID and secure invite key." }, context.RequestAborted);
                await CloseSocketAsync(socket, WebSocketCloseStatus.PolicyViolation, "Invalid room request");
                return;
            }

            bool success;
            string? inviteKey = null;
            if (type == "create")
            {
                success = hub.TryCreate(roomId, socket, out client, out inviteKey);
            }
            else if (type == "resume")
            {
                success = hub.TryResumeHost(roomId, password, socket, out client);
            }
            else
            {
                success = hub.TryJoin(roomId, password, socket, out client);
            }

            if (!success || client is null)
            {
                var message = type switch
                {
                    "create" => "That room ID is already in use.",
                    "resume" => hub.GetResumeError(roomId, password),
                    _ => hub.GetJoinError(roomId, password)
                };
                await SendJsonAsync(socket, new { type = "error", message }, context.RequestAborted);
                await CloseSocketAsync(socket, WebSocketCloseStatus.PolicyViolation, message);
                return;
            }

            var iceServers = CreateIceServers(context.RequestServices.GetRequiredService<IConfiguration>());
            if (type == "create")
            {
                await SendJsonAsync(socket, new { type = "created", room = roomId, key = inviteKey, iceServers }, context.RequestAborted);
            }
            else if (type == "resume")
            {
                await SendJsonAsync(socket, new { type = "resumed", room = roomId, iceServers }, context.RequestAborted);
            }
            else
            {
                await SendJsonAsync(socket, new { type = "joined", room = roomId, iceServers }, context.RequestAborted);
            }
        }

        if (client.Role == RoomHub.ClientRole.Guest || requestType == "resume")
        {
            var otherPeer = hub.GetOtherPeer(client);
            if (otherPeer is not null)
            {
                await hub.SendAsync(otherPeer, new { type = "peer-joined" }, context.RequestAborted);
            }
        }

        while (socket.State == WebSocketState.Open && !context.RequestAborted.IsCancellationRequested)
        {
            var message = await ReceiveMessageAsync(socket, context.RequestAborted);
            if (message is null)
            {
                break;
            }

            using var document = JsonDocument.Parse(message);
            var messageType = ReadString(document.RootElement, "type");
            if (messageType == "end")
            {
                if (client.Role != RoomHub.ClientRole.Host)
                {
                    await hub.SendAsync(client, new { type = "error", message = "Only the host can end the session." }, context.RequestAborted);
                    continue;
                }

                await hub.EndRoomAsync(client, WebSocketCloseStatus.NormalClosure, "Session ended");
                break;
            }

            if (messageType == "leave")
            {
                if (client.Role != RoomHub.ClientRole.Guest)
                {
                    await hub.SendAsync(client, new { type = "error", message = "Only the guest can leave the session." }, context.RequestAborted);
                    continue;
                }

                var host = hub.GetOtherPeer(client);
                await hub.LeavePermanentlyAsync(client);
                if (host is not null)
                {
                    await hub.SendAsync(host, new { type = "peer-left" }, CancellationToken.None);
                }
                break;
            }

            if (messageType is not ("offer" or "answer" or "ice" or "ready" or "stopped"))
            {
                await hub.SendAsync(client, new { type = "error", message = "Unsupported signaling message." }, context.RequestAborted);
                continue;
            }

            var otherPeer = hub.GetOtherPeer(client);
            if (otherPeer is not null)
            {
                await hub.SendRawAsync(otherPeer, message, context.RequestAborted);
            }
        }
    }
    catch (JsonException)
    {
        if (client is not null)
        {
            await hub.SendAsync(client, new { type = "error", message = "Invalid signaling message." }, CancellationToken.None);
        }
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
    }
    catch (WebSocketException)
    {
    }
    finally
    {
        if (client is not null)
        {
            var otherPeer = hub.GetOtherPeer(client);
            var disconnected = await hub.LeaveAsync(client);
            if (disconnected && otherPeer is not null)
            {
                await hub.SendAsync(otherPeer, new { type = "peer-disconnected" }, CancellationToken.None);
            }
        }
    }
}

static string GetRateLimitPartitionKey(HttpContext context)
{
    return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

static bool IsSameOrigin(HttpContext context)
{
    var origin = context.Request.Headers.Origin.ToString();
    if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
        originUri.Scheme is not ("http" or "https"))
    {
        return false;
    }

    var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
    var publicOrigin = configuration["PUBLIC_ORIGIN"];
    if (!string.IsNullOrWhiteSpace(publicOrigin))
    {
        return Uri.TryCreate(publicOrigin, UriKind.Absolute, out var expectedOrigin) &&
            string.Equals(originUri.Scheme, expectedOrigin.Scheme, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(originUri.Authority, expectedOrigin.Authority, StringComparison.OrdinalIgnoreCase);
    }

    return string.Equals(originUri.Authority, context.Request.Host.Value, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(originUri.Scheme, context.Request.Scheme, StringComparison.OrdinalIgnoreCase);
}

static bool IsValidInviteKey(string key)
{
    return key.Length == 43 &&
        key.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}

static List<Dictionary<string, object>> CreateIceServers(IConfiguration configuration)
{
    var servers = new List<Dictionary<string, object>>
    {
        new() { ["urls"] = "stun:stun.l.google.com:19302" }
    };

    var turnUrl = configuration["TURN_URL"];
    var sharedSecret = configuration["TURN_SHARED_SECRET"];
    if (!string.IsNullOrWhiteSpace(turnUrl) && !string.IsNullOrWhiteSpace(sharedSecret))
    {
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var username = $"{expiresAt}:{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}";
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(sharedSecret));
        var credential = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(username)));
        servers.Add(new Dictionary<string, object>
        {
            ["urls"] = turnUrl.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            ["username"] = username,
            ["credential"] = credential
        });
    }

    return servers;
}

static string? ReadString(JsonElement element, string propertyName)
{
    return element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind == JsonValueKind.String
        ? property.GetString()
        : null;
}

static async Task<byte[]?> ReceiveMessageAsync(WebSocket socket, CancellationToken cancellationToken)
{
    const int maximumMessageBytes = 128 * 1024;
    var buffer = new byte[4096];
    using var message = new MemoryStream();

    while (true)
    {
        var result = await socket.ReceiveAsync(buffer.AsMemory(), cancellationToken);
        if (result.MessageType == WebSocketMessageType.Close)
        {
            return null;
        }
        if (result.MessageType != WebSocketMessageType.Text)
        {
            throw new JsonException("Only JSON text messages are supported.");
        }
        if (message.Length + result.Count > maximumMessageBytes)
        {
            throw new JsonException("Signaling message is too large.");
        }

        message.Write(buffer, 0, result.Count);
        if (result.EndOfMessage)
        {
            return message.ToArray();
        }
    }
}

static async Task SendJsonAsync(WebSocket socket, object value, CancellationToken cancellationToken)
{
    var message = JsonSerializer.SerializeToUtf8Bytes(value);
    await socket.SendAsync(message.AsMemory(), WebSocketMessageType.Text, true, cancellationToken);
}

static async Task CloseSocketAsync(WebSocket socket, WebSocketCloseStatus status, string description)
{
    if (socket.State == WebSocketState.Open)
    {
        await socket.CloseAsync(status, description, CancellationToken.None);
    }
}

sealed class RoomHub
{
    private static readonly TimeSpan ReconnectGracePeriod = TimeSpan.FromSeconds(60);
    private readonly ConcurrentDictionary<string, Room> rooms = new(StringComparer.OrdinalIgnoreCase);

    public bool TryCreate(string roomId, WebSocket socket, out Client? client, out string? inviteKey)
    {
        client = null;
        inviteKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var room = new Room(roomId, HashPassword(inviteKey));
        var host = new Client(room, ClientRole.Host, socket);
        room.Host = host;
        if (!rooms.TryAdd(roomId, room))
        {
            inviteKey = null;
            return false;
        }

        client = host;
        return true;
    }

    public bool TryJoin(string roomId, string password, WebSocket socket, out Client? client)
    {
        client = null;
        if (!rooms.TryGetValue(roomId, out var room))
        {
            return false;
        }

        lock (room.SyncRoot)
        {
            if (!PasswordsMatch(room.PasswordHash, password) ||
                room.Host is null ||
                room.Guest is { IsOnline: true })
            {
                return false;
            }

            if (room.Guest is not null)
            {
                room.Guest.DisconnectTimeout?.Cancel();
            }
            var guest = new Client(room, ClientRole.Guest, socket);
            room.Guest = guest;
            client = guest;
            return true;
        }
    }

    public bool TryResumeHost(string roomId, string password, WebSocket socket, out Client? client)
    {
        client = null;
        if (!rooms.TryGetValue(roomId, out var room))
        {
            return false;
        }

        lock (room.SyncRoot)
        {
            if (!PasswordsMatch(room.PasswordHash, password) ||
                room.Host is null ||
                room.Host.IsOnline)
            {
                return false;
            }

            room.Host.DisconnectTimeout?.Cancel();
            var host = new Client(room, ClientRole.Host, socket);
            room.Host = host;
            client = host;
            return true;
        }
    }

    public string GetJoinError(string roomId, string password)
    {
        if (!rooms.TryGetValue(roomId, out var room))
        {
            return "Invalid room ID or secure invite key.";
        }

        lock (room.SyncRoot)
        {
            if (!PasswordsMatch(room.PasswordHash, password))
            {
                return "Invalid room ID or secure invite key.";
            }
            if (room.Host is null)
            {
                return "This session is no longer available.";
            }
            if (room.Guest is { IsOnline: true })
            {
                return "This room already has a guest connected.";
            }
        }

        return "Could not join this room. Try again.";
    }

    public string GetResumeError(string roomId, string password)
    {
        if (!rooms.TryGetValue(roomId, out var room))
        {
            return "This session is no longer available.";
        }

        lock (room.SyncRoot)
        {
            if (!PasswordsMatch(room.PasswordHash, password))
            {
                return "Invalid room ID or secure invite key.";
            }
            if (room.Host is { IsOnline: true })
            {
                return "The host is already connected.";
            }
            if (room.Host is null)
            {
                return "This session is no longer available.";
            }
        }

        return "Could not resume this session. Try again.";
    }

    public Client? GetOtherPeer(Client client)
    {
        lock (client.Room.SyncRoot)
        {
            var otherPeer = client.Role == ClientRole.Host ? client.Room.Guest : client.Room.Host;
            return otherPeer is { IsOnline: true } ? otherPeer : null;
        }
    }

    public async Task SendAsync(Client client, object value, CancellationToken cancellationToken)
    {
        var message = JsonSerializer.SerializeToUtf8Bytes(value);
        await SendRawAsync(client, message, cancellationToken);
    }

    public async Task SendRawAsync(Client client, byte[] message, CancellationToken cancellationToken)
    {
        if (client.Socket.State != WebSocketState.Open)
        {
            return;
        }

        await client.SendLock.WaitAsync(cancellationToken);
        try
        {
            if (client.Socket.State == WebSocketState.Open)
            {
                await client.Socket.SendAsync(message.AsMemory(), WebSocketMessageType.Text, true, cancellationToken);
            }
        }
        finally
        {
            client.SendLock.Release();
        }
    }

    public async Task CloseAsync(Client client, WebSocketCloseStatus status, string description)
    {
        await client.SendLock.WaitAsync();
        try
        {
            if (client.Socket.State == WebSocketState.Open)
            {
                await client.Socket.CloseOutputAsync(status, description, CancellationToken.None);
            }
        }
        finally
        {
            client.SendLock.Release();
        }
    }

    public Task<bool> LeaveAsync(Client client)
    {
        var room = client.Room;
        CancellationTokenSource? timeout = null;
        lock (room.SyncRoot)
        {
            var isCurrentClient = client.Role == ClientRole.Host
                ? ReferenceEquals(room.Host, client)
                : ReferenceEquals(room.Guest, client);
            if (isCurrentClient && client.IsOnline)
            {
                client.IsOnline = false;
                timeout = new CancellationTokenSource();
                client.DisconnectTimeout = timeout;
            }
        }

        if (timeout is not null)
        {
            _ = ExpireDisconnectedClientAsync(client, timeout);
        }

        return Task.FromResult(timeout is not null);
    }

    public Task LeavePermanentlyAsync(Client client)
    {
        var room = client.Room;
        lock (room.SyncRoot)
        {
            if (ReferenceEquals(room.Guest, client))
            {
                client.IsOnline = false;
                client.DisconnectTimeout?.Cancel();
                client.DisconnectTimeout = null;
                room.Guest = null;
            }

            if (room.Host is null && room.Guest is null)
            {
                ((ICollection<KeyValuePair<string, Room>>)rooms).Remove(new(room.Id, room));
            }
        }

        return Task.CompletedTask;
    }

    private async Task ExpireDisconnectedClientAsync(Client client, CancellationTokenSource timeout)
    {
        try
        {
            await Task.Delay(ReconnectGracePeriod, timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            timeout.Dispose();
            return;
        }

        try
        {
            var room = client.Room;
            Client? peerToClose = null;
            lock (room.SyncRoot)
            {
                var isCurrentClient = client.Role == ClientRole.Host
                    ? ReferenceEquals(room.Host, client)
                    : ReferenceEquals(room.Guest, client);
                if (!isCurrentClient || client.IsOnline)
                {
                    return;
                }

                client.DisconnectTimeout = null;
                if (client.Role == ClientRole.Host)
                {
                    room.Host = null;
                    peerToClose = room.Guest;
                    room.Guest = null;
                }
                else
                {
                    room.Guest = null;
                }

                if (room.Host is null && room.Guest is null)
                {
                    ((ICollection<KeyValuePair<string, Room>>)rooms).Remove(new(room.Id, room));
                }
            }

            if (peerToClose is not null)
            {
                try
                {
                    await NotifySessionEndedAsync(
                        peerToClose,
                        WebSocketCloseStatus.NormalClosure,
                        "Session expired after network disconnection");
                }
                catch (WebSocketException)
                {
                }
            }
        }
        finally
        {
            timeout.Dispose();
        }
    }

    public async Task EndRoomAsync(Client client, WebSocketCloseStatus status, string description)
    {
        var room = client.Room;
        Client? otherPeer;
        lock (room.SyncRoot)
        {
            otherPeer = client.Role == ClientRole.Host ? room.Guest : room.Host;
            room.Host?.DisconnectTimeout?.Cancel();
            room.Guest?.DisconnectTimeout?.Cancel();
            room.Host = null;
            room.Guest = null;
            client.IsOnline = false;
            ((ICollection<KeyValuePair<string, Room>>)rooms).Remove(new(room.Id, room));
        }

        if (otherPeer is not null)
        {
            await NotifySessionEndedAsync(otherPeer, status, description);
        }
    }

    private async Task NotifySessionEndedAsync(Client client, WebSocketCloseStatus status, string description)
    {
        await SendAsync(client, new { type = "session-ended" }, CancellationToken.None);
        await CloseAsync(client, status, description);
    }

    private static byte[] HashPassword(string password) => SHA256.HashData(Encoding.UTF8.GetBytes(password));

    private static bool PasswordsMatch(byte[] expectedHash, string actualPassword)
    {
        var actualHash = HashPassword(actualPassword);
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    public sealed class Room(string id, byte[] passwordHash)
    {
        public string Id { get; } = id;
        public byte[] PasswordHash { get; } = passwordHash;
        public object SyncRoot { get; } = new();
        public Client? Host { get; set; }
        public Client? Guest { get; set; }
    }

    public enum ClientRole
    {
        Host,
        Guest
    }

    public sealed class Client(Room room, ClientRole role, WebSocket socket)
    {
        public Room Room { get; } = room;
        public ClientRole Role { get; } = role;
        public WebSocket Socket { get; } = socket;
        public SemaphoreSlim SendLock { get; } = new(1, 1);
        public bool IsOnline { get; set; } = true;
        public CancellationTokenSource? DisconnectTimeout { get; set; }
    }
}
