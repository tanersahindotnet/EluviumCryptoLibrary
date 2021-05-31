using System.Security.Cryptography;
using System.Text;

namespace EluviumCryptoLibrary.Services.HashingService
{
    public class HashingService:IHashingService
    {
        public string MultipleHash(string value)
        {
            var sha512 = Sha512(value);
            var sha384 = Sha384(sha512);
            var finalSha256 = Sha256(sha384);
            return finalSha256;
        }

        public string Sha256(string input)
        {
            // Create a SHA256
            using (var sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array
                var bytes = sha256Hash.ComputeHash(Encoding.Unicode.GetBytes(input));
                // Convert byte array to a string
                var builder = new StringBuilder();
                foreach (var t in bytes)
                {
                    builder.Append(t.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public string Sha384(string input)
        {
            using (var sha384Hash = SHA384.Create())
            {
                // ComputeHash - returns byte array
                var bytes = sha384Hash.ComputeHash(Encoding.Unicode.GetBytes(input));
                // Convert byte array to a string
                var builder = new StringBuilder();
                foreach (var t in bytes)
                {
                    builder.Append(t.ToString("x2"));
                }
                return builder.ToString();
            }
        }
        public string Sha512(string input)
        {
            using (var sha512Hash = SHA512.Create())
            {
                // ComputeHash - returns byte array
                var bytes = sha512Hash.ComputeHash(Encoding.Unicode.GetBytes(input));
                // Convert byte array to a string
                var builder = new StringBuilder();
                foreach (var t in bytes)
                {
                    builder.Append(t.ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
