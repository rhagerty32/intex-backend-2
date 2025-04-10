using Microsoft.Data.Sqlite;
using DotNetEnv;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using FuzzySharp;
using System.Collections.Generic;
using System.Linq;
using CineNicheAPI.Models;
using FuzzySharp.SimilarityRatio.Scorer;
using FuzzySharp.PreProcess;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
            "http://localhost:5173",
            "https://zealous-water-0b3cb241e.6.azurestaticapps.net"
        )
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials();
    });
});

var app = builder.Build();
app.UseCors("AllowFrontend");

// Redirect HTTP to HTTPS
app.UseHttpsRedirection();

// Enable HSTS (HTTP Strict Transport Security) in production only
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

string DB_PATH = "Data Source=unified_movies.db";

app.Use(async (context, next) =>
{
    var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
    string userType = "unauthenticated"; // default

    if (authHeader != null && authHeader.StartsWith("Bearer "))
    {
        var token = authHeader.Substring("Bearer ".Length).Trim();
        var handler = new JwtSecurityTokenHandler();

        try
        {
            var jwtToken = handler.ReadJwtToken(token);

            var claims = new Dictionary<string, object>();
            foreach (var claim in jwtToken.Claims)
            {
                try
                {
                    if (claim.Value.StartsWith("{") || claim.Value.StartsWith("["))
                    {
                        using var doc = JsonDocument.Parse(claim.Value);
                        claims[claim.Type] = doc.RootElement.Clone();
                    }
                    else
                    {
                        claims[claim.Type] = claim.Value;
                    }
                }
                catch
                {
                    claims[claim.Type] = claim.Value;
                }
            }

            Console.WriteLine("🔐 JWT Claims:");
            foreach (var kvp in claims)
            {
                var value = kvp.Value is JsonElement el ? el.ToString() : kvp.Value?.ToString();
                Console.WriteLine($"   {kvp.Key}: {value}");
            }

            context.Items["jwt"] = claims;

            // Set userType
            var email = claims.TryGetValue("email", out var e) ? e.ToString()?.ToLower() : null;
            if (email == "ry2402@gmail.com" || email == "ryan@spotparking.app")
            {
                userType = "admin";
            }
            else if (!string.IsNullOrWhiteSpace(email))
            {
                userType = "authenticated";
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("⚠️ Failed to decode JWT: " + ex.Message);
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Invalid token");
            return;
        }
    }

    context.Items["userType"] = userType;
    Console.WriteLine($"🧠 User type: {userType}");

    await next();
});

// 🧠 SQL Query Helper
List<Dictionary<string, object>> RunQuery(string sql, object[]? values = null)
{
    var results = new List<Dictionary<string, object>>();
    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();
    using var command = connection.CreateCommand();
    command.CommandText = sql;

    if (values != null)
    {
        for (int i = 0; i < values.Length; i++)
        {
            command.Parameters.AddWithValue($"@p{i}", values[i]);
        }
    }

    using var reader = command.ExecuteReader();
    while (reader.Read())
    {
        var row = new Dictionary<string, object>();
        for (int i = 0; i < reader.FieldCount; i++)
        {
            row[reader.GetName(i)] = reader.GetValue(i);
        }
        results.Add(row);
    }

    return results;
}

// 👤 JWT Decoding Helper
JsonElement? DecodeJwtPayload(HttpRequest req)
{
    var authHeader = req.Headers["Authorization"].FirstOrDefault();

    if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
    {
        var token = authHeader.Substring("Bearer ".Length);
        var parts = token.Split('.');

        if (parts.Length == 3)
        {
            try
            {
                var payload = parts[1];
                var jsonBytes = Convert.FromBase64String(PadBase64(payload));
                return JsonDocument.Parse(jsonBytes).RootElement;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ JWT decoding failed: {ex.Message}");
            }
        }
    }

    return null;
}

string PadBase64(string base64)
{
    return base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
}

app.MapPost("/check-user", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();
    var json = JsonDocument.Parse(body).RootElement;

    if (!json.TryGetProperty("email", out var emailProp) || string.IsNullOrWhiteSpace(emailProp.GetString()))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing email");
        return;
    }

    var email = emailProp.GetString()!;

    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();

    using var checkCommand = connection.CreateCommand();
    checkCommand.CommandText = "select user_id, admin from users where lower(email) = lower(@p0) limit 1";
    checkCommand.Parameters.AddWithValue("@p0", email);

    using var readerDb = checkCommand.ExecuteReader();

    if (readerDb.Read())
    {
        var userId = readerDb.GetValue(0).ToString(); // user_id
        var isAdmin = readerDb.GetInt32(1) == 1;       // admin
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { exists = true, admin = isAdmin, user_id = userId });
    }
    else
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { exists = false, admin = false, user_id = (string?)null });
    }
});

app.MapPost("/auth", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();
    var json = JsonDocument.Parse(body).RootElement;

    // 🔐 Safely pull email
    if (!json.TryGetProperty("email", out var emailProp) || string.IsNullOrWhiteSpace(emailProp.GetString()))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing email");
        return;
    }
    var email = emailProp.GetString()!;

    // 👤 Construct name
    string name;
    if (json.TryGetProperty("first_name", out var firstNameProp) &&
        json.TryGetProperty("last_name", out var lastNameProp))
    {
        var firstName = firstNameProp.GetString() ?? "";
        var lastName = lastNameProp.GetString() ?? "";
        name = $"{firstName} {lastName}".Trim();
    }
    else if (json.TryGetProperty("name", out var nameProp))
    {
        name = nameProp.GetString() ?? "";
    }
    else
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing name or first/last name");
        return;
    }

    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();

    // 🔍 Check if user already exists by email
    using (var checkCommand = connection.CreateCommand())
    {
        checkCommand.CommandText = "select count(*) from users where lower(email) = lower(@p0)";
        checkCommand.Parameters.AddWithValue("@p0", email);

        var count = Convert.ToInt32(checkCommand.ExecuteScalar());

        if (count > 0)
        {
            var response = new { authenticated = true };
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(response);
            return;
        }
    }

    // ➕ Insert new user if not found
    using (var insertCommand = connection.CreateCommand())
    {
        insertCommand.CommandText = @"
            insert into users (
                name, email, phone, age, gender,
                Netflix, Amazon_Prime, ""Disney+"", ""Paramount+"",
                Max, Hulu, ""Apple_TV+"", Peacock,
                city, state, zip, admin
            ) values (
                @p0, @p1, null, null, null,
                0, 0, 0, 0,
                0, 0, 0, 0,
                null, null, null, 0
            )";
        insertCommand.Parameters.AddWithValue("@p0", name);
        insertCommand.Parameters.AddWithValue("@p1", email);
        insertCommand.ExecuteNonQuery();
    }

    // ✅ Return success
    var successResponse = new { authenticated = true };
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsJsonAsync(successResponse);
});


app.MapGet("/superSearch", (HttpRequest req) =>
{
    var query = req.Query["q"].ToString().ToLower();

    if (string.IsNullOrWhiteSpace(query))
    {
        Console.WriteLine("⚠️ Empty query received.");
        return Results.BadRequest("Search query 'q' is required.");
    }

    var sql = "select * from titles";
    var allTitles = RunQuery(sql);

    var seenBlobs = new HashSet<string>();
    var indexed = allTitles.Select((row, idx) =>
    {
        var genreKeywords = row
            .Where(kv => kv.Value?.ToString() == "1" && kv.Key != null)
            .Select(kv => kv.Key.ToLower());

        var blobParts = new[]
        {
            row.GetValueOrDefault("title")?.ToString()?.ToLower(),
            row.GetValueOrDefault("description")?.ToString()?.ToLower(),
            row.GetValueOrDefault("director")?.ToString()?.ToLower(),
            row.GetValueOrDefault("country")?.ToString()?.ToLower(),
            string.Join(" ", genreKeywords)
        };

        var rawBlob = string.Join(" ", blobParts.Where(p => !string.IsNullOrWhiteSpace(p)));
        var uniqueBlob = rawBlob;

        // Make the key unique if already used
        int suffix = 1;
        while (!seenBlobs.Add(uniqueBlob))
        {
            uniqueBlob = $"{rawBlob}__{suffix}";
            suffix++;
        }

        return new SearchableMovie
        {
            Data = row,
            SearchBlob = uniqueBlob
        };
    }).ToList();

    var blobToMovie = indexed.ToDictionary(m => m.SearchBlob, m => m.Data);

    var matches = Process.ExtractTop(
        query,
        blobToMovie.Keys,
        s => s,
        limit: 50
    );

    var results = matches
        .Select(match => blobToMovie[match.Value])
        .ToList();

    return Results.Ok(results);
});




app.MapPost("/add-movie", async (HttpRequest req) =>
{
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        // ✅ Only allow admin
        if (email != "ry2402@gmail.com" && email != "ryan@spotparking.app")
        {
            Console.WriteLine("🚫 Access denied: not an admin.");
            return Results.Unauthorized(); // or throw or return your error type
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var json = await JsonDocument.ParseAsync(req.Body);
    var body = new Dictionary<string, object>();

    foreach (var prop in json.RootElement.EnumerateObject())
    {
        var val = prop.Value;

        // Safely convert JsonElement to CLR types
        body[prop.Name] = val.ValueKind switch
        {
            JsonValueKind.Number => val.TryGetInt32(out var intVal) ? intVal : val.GetDouble(),
            JsonValueKind.String => val.GetString() ?? "",
            JsonValueKind.True => 1,
            JsonValueKind.False => 0,
            _ => DBNull.Value
        };
    }

    // Generate a unique show_id
    body["show_id"] = Guid.NewGuid().ToString();

    var fields = body.Keys.ToList();
    var columns = string.Join(", ", fields.Select(f => $"\"{f}\""));
    var placeholders = string.Join(", ", fields.Select((_, i) => $"@p{i}"));

    var sql = $"INSERT INTO titles ({columns}) VALUES ({placeholders})";

    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();

    using var command = connection.CreateCommand();
    command.CommandText = sql;

    for (int i = 0; i < fields.Count; i++)
    {
        command.Parameters.AddWithValue($"@p{i}", body[fields[i]] ?? DBNull.Value);
    }

    try
    {
        command.ExecuteNonQuery();
        return Results.Ok(new { success = true, show_id = body["show_id"] });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to insert movie: {ex.Message}");
    }
});

app.MapPatch("/patch-movie", async (HttpContext context) =>
{
    if (context.Request.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        // ✅ Only allow admin
        if (email != "ry2402@gmail.com" && email != "ryan@spotparking.app")
        {
            Console.WriteLine("🚫 Access denied: not an admin.");
            return Results.Unauthorized(); // or throw or return your error type
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();
    var json = JsonDocument.Parse(body).RootElement;

    if (!json.TryGetProperty("show_id", out var showIdProp) || string.IsNullOrWhiteSpace(showIdProp.GetString()))
    {
        return Results.BadRequest("Missing or invalid show_id.");
    }

    var showId = showIdProp.GetString()!;
    var updates = new List<string>();
    var parameters = new List<object>();
    int paramIndex = 0;

    foreach (var prop in json.EnumerateObject())
    {
        if (prop.Name == "show_id") continue;

        updates.Add($"{prop.Name} = @p{paramIndex}");
        parameters.Add(prop.Value.ValueKind switch
        {
            JsonValueKind.Number => prop.Value.TryGetInt32(out var iVal) ? iVal : (object)prop.Value.GetDecimal(),
            JsonValueKind.String => prop.Value.GetString() ?? "",
            JsonValueKind.True => 1,
            JsonValueKind.False => 0,
            _ => DBNull.Value
        });

        paramIndex++;
    }

    if (!updates.Any())
    {
        return Results.BadRequest("No fields to update.");
    }

    parameters.Add(showId); // Add show_id as the last parameter

    var sql = $"UPDATE titles SET {string.Join(", ", updates)} WHERE show_id = @p{paramIndex}";

    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();
    using var command = connection.CreateCommand();
    command.CommandText = sql;

    for (int i = 0; i < parameters.Count; i++)
    {
        command.Parameters.AddWithValue($"@p{i}", parameters[i]);
    }

    var rowsAffected = command.ExecuteNonQuery();
    if (rowsAffected > 0)
    {
        return Results.Ok(new { success = true });
    }
    else
    {
        return Results.NotFound("Movie not found or nothing updated.");
    }
});

app.MapPost("/delete-movie", async (HttpContext context) =>
{
    if (context.Request.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        // ✅ Only allow admin
        if (email != "ry2402@gmail.com" && email != "ryan@spotparking.app")
        {
            Console.WriteLine("🚫 Access denied: not an admin.");
            return Results.Unauthorized(); // or throw or return your error type
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();

    if (string.IsNullOrWhiteSpace(body))
    {
        return Results.BadRequest("Missing request body.");
    }

    var json = JsonDocument.Parse(body).RootElement;

    if (!json.TryGetProperty("show_id", out var showIdProp) || string.IsNullOrWhiteSpace(showIdProp.GetString()))
    {
        return Results.BadRequest("Missing or invalid show_id.");
    }

    var showId = showIdProp.GetString();

    using var connection = new SqliteConnection(DB_PATH);
    connection.Open();

    using var deleteCommand = connection.CreateCommand();
    deleteCommand.CommandText = "delete from titles where show_id = @p0";
    deleteCommand.Parameters.AddWithValue("@p0", showId);

    var rowsAffected = deleteCommand.ExecuteNonQuery();

    if (rowsAffected > 0)
    {
        return Results.Ok(new { success = true });
    }
    else
    {
        return Results.NotFound("Movie not found.");
    }
});


//^ DONEEEEEEE
app.MapGet("/search", async (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var query = req.Query["q"].ToString().ToLower();

    if (string.IsNullOrWhiteSpace(query))
    {
        Console.WriteLine("⚠️ Empty query received.");
        return Results.BadRequest("Search query 'q' is required.");
    }

    var sql = "select * from titles";
    var allTitles = RunQuery(sql);

    var indexed = allTitles.Select(row =>
    {
        var genreKeywords = row
            .Where(kv => kv.Value?.ToString() == "1" && kv.Key != null)
            .Select(kv => kv.Key.ToLower());

        var blobParts = new[]
        {
            row.GetValueOrDefault("title")?.ToString()?.ToLower(),
            row.GetValueOrDefault("description")?.ToString()?.ToLower(),
            row.GetValueOrDefault("director")?.ToString()?.ToLower(),
            row.GetValueOrDefault("country")?.ToString()?.ToLower(),
            string.Join(" ", genreKeywords)
        };

        return new SearchableMovie
        {
            Title = row.GetValueOrDefault("title")?.ToString(),
            Type = row.GetValueOrDefault("type")?.ToString(),
            Year = row.GetValueOrDefault("release_year")?.ToString(),
            Path = $"/title?titleID={row.GetValueOrDefault("show_id")}",
            Data = row,
            SearchBlob = string.Join(" ", blobParts.Where(p => !string.IsNullOrWhiteSpace(p)))
        };
    }).ToList();

    var blobToMovie = new Dictionary<string, SearchableMovie>();
    int counter = 0;

    foreach (var movie in indexed)
    {
        var key = movie.SearchBlob;
        while (blobToMovie.ContainsKey(key))
        {
            counter++;
            key = $"{movie.SearchBlob}_{counter}";
        }
        blobToMovie[key] = movie;
    }

    var matches = Process.ExtractTop(
        query,
        blobToMovie.Keys,
        s => s,
        limit: 25
    );

    var results = matches
        .Select(match => new
        {
            title = blobToMovie[match.Value].Title,
            type = blobToMovie[match.Value].Type,
            year = blobToMovie[match.Value].Year,
            path = blobToMovie[match.Value].Path,
            score = match.Score,
        })
        .ToList();

    return Results.Ok(results);
});





app.MapGet("/singleTitle", (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var query = req.Query;

    if (!query.TryGetValue("title", out var titleVal) || string.IsNullOrWhiteSpace(titleVal))
    {
        return Results.BadRequest(new { error = "Missing title parameter" });
    }

    string sql = @"
        select * from titles 
        where lower(title) like lower(@p0) 
        limit 1";

    var parameters = new object[] { $"%{titleVal.ToString()}%" };

    var result = RunQuery(sql, parameters);

    if (result.Count == 0)
    {
        return Results.NotFound(new { message = "Title not found" });
    }

    return Results.Ok(result[0]);
});

app.MapGet("/getAllTitles", (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var query = req.Query;

    // 🧭 Pagination
    int pageSize = query.TryGetValue("pageSize", out var pageSizeVal) && int.TryParse(pageSizeVal, out var parsedSize) ? parsedSize : 10;
    int pageNumber = query.TryGetValue("pageNumber", out var pageNumVal) && int.TryParse(pageNumVal, out var parsedPage) ? parsedPage : 0;
    int offset = pageSize * pageNumber;

    var filters = new List<string>();
    var parameters = new List<object>();
    int paramIndex = 0;

    foreach (var (key, values) in query)
    {
        if (key is "pageSize" or "pageNumber") continue;

        // Special handling for genre filters (they are column names with value = 1)
        if (key.ToLower() == "genre")
        {
            foreach (var genreVal in values)
            {
                filters.Add($"\"{genreVal}\" = '1'");
            }
            continue;
        }

        // Skip empty values
        if (values.Count == 0 || string.IsNullOrWhiteSpace(values[0]))
            continue;

        if (values.Count > 1)
        {
            var placeholders = string.Join(",", values.Select((_, i) => $"@p{paramIndex + i}"));
            filters.Add($"{key} IN ({placeholders})");
            parameters.AddRange(values);
            paramIndex += values.Count;
        }
        else
        {
            filters.Add($"{key} = @p{paramIndex}");
            parameters.Add(values[0]);
            paramIndex++;
        }
    }

    var whereClause = filters.Any() ? $"WHERE {string.Join(" AND ", filters)}" : "";

    string sql = $@"
        SELECT * FROM titles
        {whereClause}
        LIMIT @p{paramIndex} OFFSET @p{paramIndex + 1}
    ";
    parameters.Add(pageSize);
    parameters.Add(offset);

    var results = RunQuery(sql, parameters.ToArray());
    return Results.Ok(results);
});

app.MapGet("/countries", (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    string sql = "select distinct country from titles where country is not null and trim(country) != ''";
    var result = RunQuery(sql);

    var countries = result
        .Select(row => row.GetValueOrDefault("country")?.ToString())
        .Where(c => !string.IsNullOrWhiteSpace(c))
        .Distinct()
        .OrderBy(c => c)
        .ToList();

    return Results.Ok(countries);
});


// 🎬 /titles (supports filtering by multiple values like ?title=A&title=B)
app.MapGet("/titles", (HttpRequest req) =>
{
    var query = req.Query;

    bool countOnly = query.TryGetValue("countOnly", out var countOnlyVal) && bool.TryParse(countOnlyVal, out var parsedBool) && parsedBool;
    int count = query.TryGetValue("count", out var countVal) && int.TryParse(countVal, out var parsedCount) ? parsedCount : 100;

    var filters = new List<string>();
    var parameters = new List<object>();
    int paramIndex = 0;

    // Special filters for type and genre
    if (query.TryGetValue("type", out var typeVal))
    {
        filters.Add($"type = @p{paramIndex}");
        parameters.Add(typeVal.ToString());
        paramIndex++;
    }

    if (query.TryGetValue("genre", out var genreVal))
    {
        filters.Add($"\"{genreVal}\" = '1'");
    }

    // Support other filters (like release_year, country, etc.)
    foreach (var key in query.Keys)
    {
        if (key is "countOnly" or "count" or "type" or "genre") continue;

        var values = query[key];

        if (values.Count > 1)
        {
            var placeholders = string.Join(",", values.Select((_, i) => $"@p{paramIndex + i}"));
            filters.Add($"{key} IN ({placeholders})");
            parameters.AddRange(values.Select(v => (object)v));
            paramIndex += values.Count;
        }
        else
        {
            filters.Add($"{key} = @p{paramIndex}");
            parameters.Add(values[0]);
            paramIndex++;
        }
    }

    var whereClause = filters.Any() ? $"WHERE {string.Join(" AND ", filters)}" : "";

    if (countOnly)
    {
        string sql = $"SELECT title, show_id FROM titles {whereClause} ORDER BY RANDOM() LIMIT @p{paramIndex}";
        parameters.Add(count);

        var result = RunQuery(sql, parameters.ToArray());
        var titles = result.Select(row => new
        {
            title = row.GetValueOrDefault("title")?.ToString(),
            show_id = row.GetValueOrDefault("show_id")?.ToString()
        }).ToList();

        return Results.Ok(titles);
    }

    // If specific fields requested (frontend API), return only needed columns
    if (query.ContainsKey("genre") || query.ContainsKey("type") || query.ContainsKey("count"))
    {
        string sql = $"SELECT title, random_rating, show_id FROM titles {whereClause} ORDER BY RANDOM() LIMIT @p{paramIndex}";
        parameters.Add(count);
        return Results.Ok(RunQuery(sql, parameters.ToArray()));
    }

    // Default: return full results with any filters applied
    string fullSql = $"SELECT * FROM titles {whereClause} LIMIT 100";
    return Results.Ok(RunQuery(fullSql, parameters.ToArray()));
});

app.MapPost("/titles", async (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    try
    {
        var body = await req.ReadFromJsonAsync<Dictionary<string, List<string>>>();

        if (body == null || !body.ContainsKey("titles") || body["titles"].Count == 0)
            return Results.BadRequest("Body must include 'titles' as a non-empty list");

        var titles = body["titles"];
        var placeholders = string.Join(",", titles.Select((_, i) => $"@p{i}"));
        var sql = $"SELECT * FROM titles WHERE title IN ({placeholders})";

        return Results.Ok(RunQuery(sql, titles.Cast<object>().ToArray()));
    }
    catch
    {
        return Results.BadRequest("Invalid JSON format. Expected: { \"titles\": [\"Movie1\", \"Movie2\"] }");
    }
});

// 🎞️ /similar-movies
app.MapGet("/similar-movies", (HttpRequest req, string? title) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    if (!string.IsNullOrEmpty(title))
    {
        var result = RunQuery("SELECT * FROM combined_top5_recommendations WHERE title = @p0", new object[] { title });
        return result.Count > 0 ? Results.Ok(result[0]) : Results.NotFound("Title not found");
    }

    return Results.Ok(RunQuery("SELECT * FROM combined_top5_recommendations"));
});

// 🎯 /user-recommendations
app.MapGet("/user-recommendations", (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var query = req.Query;
    if (!query.Any())
        return Results.BadRequest("At least one query parameter is required");

    var filters = new List<string>();
    var values = new List<object>();
    int index = 0;

    foreach (var (key, val) in query)
    {
        if (val.Count > 1)
        {
            var inClause = string.Join(",", val.Select((_, i) => $"@p{index + i}"));
            filters.Add($"{key} IN ({inClause})");
            values.AddRange(val.Select(v => v.ToString()));
            index += val.Count;
        }
        else
        {
            filters.Add($"{key} = @p{index}");
            values.Add(val.ToString());
            index++;
        }
    }

    string sql = $"SELECT * FROM personalized_recommendations WHERE {string.Join(" AND ", filters)}";
    var result = RunQuery(sql, values.ToArray());
    return result.Count > 0 ? Results.Ok(result) : Results.NotFound("No matches found");
});

app.MapPost("/user-ratings", async (HttpContext context, UserRatingDto body) =>
{
    /// 🔐 JWT auth check
    if (context.Request.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email &&
        !string.IsNullOrWhiteSpace(email))
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }
    
    if (string.IsNullOrWhiteSpace(body.show_id) || string.IsNullOrWhiteSpace(body.user_id) || body.rating_id == 0)
    {
        Console.WriteLine("❌ Missing or empty fields");
        return Results.BadRequest("Missing or empty fields");
    }

    string deleteSql = "DELETE FROM movie_ratings WHERE show_id = @p0 AND user_id = @p1";
    RunQuery(deleteSql, new object[] { body.show_id, body.user_id });

    string insertSql = "INSERT INTO movie_ratings (show_id, user_id, rating) VALUES (@p0, @p1, @p2)";
    RunQuery(insertSql, new object[] { body.show_id, body.user_id, body.rating_id });

    Console.WriteLine($"✅ Saved rating: {body.rating_id} for show {body.show_id}, user {body.user_id}");

    return Results.Ok(new
    {
        success = true,
        show_id = body.show_id,
        user_id = body.user_id,
        rating = body.rating_id
    });
});

app.MapGet("/user-ratings", (HttpRequest req) =>
{
    // 🔐 JWT auth check
    if (req.HttpContext.Items["jwt"] is Dictionary<string, object> jwtClaims &&
        jwtClaims.TryGetValue("email", out var emailObj) &&
        emailObj is string email)
    {
        Console.WriteLine($"🔐 Authenticated user: {email}");

        var userType = email == "ry2402@gmail.com" ? "admin" : "authenticated";
        if (userType != "authenticated" && userType != "admin")
        {
            return Results.Unauthorized();
        }
    }
    else
    {
        Console.WriteLine("❌ No valid JWT or email found.");
        return Results.Unauthorized();
    }

    var query = req.Query;

    if (!query.TryGetValue("user_id", out var userIdVal))
    {
        return Results.BadRequest("Missing user_id");
    }

    var userId = userIdVal.ToString();

    if (query.TryGetValue("show_id", out var showIdVal))
    {
        var showId = showIdVal.ToString();
        string singleSql = "SELECT rating FROM movie_ratings WHERE user_id = @p0 AND show_id = @p1 LIMIT 1";
        var singleResult = RunQuery(singleSql, new object[] { userId, showId });

        if (singleResult.Count == 0)
        {
            return Results.Ok(new { rating = (int?)null }); // no rating found
        }

        return Results.Ok(new { rating = singleResult[0]["rating"] });
    }

    // No show_id = return all ratings for user
    string allSql = "SELECT * FROM movie_ratings WHERE user_id = @p0";
    var allResult = RunQuery(allSql, new object[] { userId });
    return Results.Ok(allResult);
});

app.Run();