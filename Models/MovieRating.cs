using System.Text.Json.Serialization;

namespace CineNicheAPI.Models
{
    public class UserRatingDto
    {
        [JsonPropertyName("show_id")]
        public string show_id { get; set; }

        [JsonPropertyName("user_id")]
        public string user_id { get; set; }

        [JsonPropertyName("rating_id")]
        public int rating_id { get; set; }
    }
}