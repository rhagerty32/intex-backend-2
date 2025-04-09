namespace CineNicheAPI.Models;

public class SearchableMovie
{
    public string? Title { get; set; }
    public string? Type { get; set; }
    public string? Year { get; set; }
    public string? Path { get; set; }
    public Dictionary<string, object?> Data { get; set; } = new();
    public string SearchBlob { get; set; } = string.Empty;
}