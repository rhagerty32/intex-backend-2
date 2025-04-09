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

var API_KEY = Environment.GetEnvironmentVariable("API_KEY") ?? "abc123";
string DB_PATH = "Data Source=unified_movies.db";

// 🔐 API Key Middleware
app.Use(async (context, next) =>
{
    var key = context.Request.Headers["X-API-Key"].FirstOrDefault();
    if (key != API_KEY)
    {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Unauthorized");
        return;
    }
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
    checkCommand.CommandText = "select admin from users where lower(email) = lower(@p0) limit 1";
    checkCommand.Parameters.AddWithValue("@p0", email);

    using var readerDb = checkCommand.ExecuteReader();

    if (readerDb.Read())
    {
        var isAdmin = readerDb.GetInt32(0) == 1;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { exists = true, admin = isAdmin });
    }
    else
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { exists = false, admin = false });
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

//^ DONEEEEEEE
app.MapGet("/api/search", (HttpRequest req) =>
{
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

    // Build dictionary: blob => movie
    var blobToMovie = indexed.ToDictionary(m => m.SearchBlob, m => m);

    // Use FuzzySharp with strings only
    var matches = Process.ExtractTop(
        query,
        blobToMovie.Keys,
        s => s,
        limit: 25
    );

    // Map fuzzy matches back to full movie info
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





app.MapGet("/api/singleTitle", (HttpRequest req) =>
{
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





// 🎬 /api/titles (supports filtering by multiple values like ?title=A&title=B)
app.MapGet("/api/titles", (HttpRequest req) =>
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

app.MapPost("/api/titles", async (HttpRequest req) =>
{
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

// 👤 /api/users
app.MapGet("/api/users", (int? user_id, string? email) =>
{
    if (user_id == null && email == null)
        return Results.BadRequest("Must provide user_id or email");

    string sql = user_id != null ? 
        "SELECT * FROM users WHERE user_id = @p0" : 
        "SELECT * FROM users WHERE email = @p0";

    var result = RunQuery(sql, new object[] { user_id?.ToString() ?? email! });
    return result.Count > 0 ? Results.Ok(result[0]) : Results.NotFound("User not found");
});

// 🎞️ /api/similar-movies
app.MapGet("/api/similar-movies", (string? title) =>
{
    if (!string.IsNullOrEmpty(title))
    {
        var result = RunQuery("SELECT * FROM combined_top5_recommendations WHERE title = @p0", new object[] { title });
        return result.Count > 0 ? Results.Ok(result[0]) : Results.NotFound("Title not found");
    }

    return Results.Ok(RunQuery("SELECT * FROM combined_top5_recommendations"));
});

// 🎯 /api/user-recommendations
app.MapGet("/api/user-recommendations", (HttpRequest req) =>
{
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

app.Run();