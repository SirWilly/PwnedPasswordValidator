using System;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace PwnedPasswordValidator
{
    /// <inheritdoc />
    public class PwnedPasswordClient : IPwnedPasswordClient
    {
        /// <summary>
        /// The default name used to register the typed HttpClient with the <see cref="IServiceCollection"/>
        /// </summary>
        public const string DefaultName = "PwnedPasswordsClient";

        private static HttpClient _httpClient;
        private readonly ILogger<PwnedPasswordClient> _logger;

        /// <summary>
        /// Create a new instance of <see cref="PwnedPasswordClient"/>
        /// </summary>
        /// <param name="httpClient">HttpClient</param>
        /// <param name="logger">Logger</param>
        public PwnedPasswordClient(HttpClient httpClient, ILogger<PwnedPasswordClient> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<bool> HasPasswordBeenPwned(string password)
        {
            var hash = password.GetSha1Hash();
            var pwnedHashes = await GetPwnedPasswordHashSuffixes(hash.Substring(0, 5));
            var hashTail = hash.Substring(5);

            var pwnedEntry = pwnedHashes.FirstOrDefault(x =>
                string.Equals(
                    x.Substring(0, x.IndexOf(":", StringComparison.OrdinalIgnoreCase)),
                    hashTail,
                    StringComparison.OrdinalIgnoreCase)
            );

            if (pwnedEntry == null)
            {
                return false;
            }

            _logger.LogWarning($"This password has been seen {pwnedEntry.Substring(pwnedEntry.IndexOf(":", StringComparison.OrdinalIgnoreCase))} times before.");
            return true;
        }

        private static async Task<string[]> GetPwnedPasswordHashSuffixes(string hashPrefix)
        {
            var response = await _httpClient.GetAsync($"https://api.pwnedpasswords.com/range/{hashPrefix}");

            if (response.StatusCode.ToString() == "429" && response.Headers.RetryAfter.Delta.HasValue)
            {
                Thread.Sleep(response.Headers.RetryAfter.Delta.Value);
                await GetPwnedPasswordHashSuffixes(hashPrefix);
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Not able to retrieve Pwned passwords list. Response status code: '{response.StatusCode}', reason: '{response.ReasonPhrase}'.");
            }

            var content = await response.Content.ReadAsStringAsync();

            return content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        }
    }
}
