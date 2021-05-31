namespace EluviumCryptoLibrary.Services.HashingService
{
    public interface IHashingService
    {
        string MultipleHash(string value);
        string Sha256(string input);
        string Sha384(string input);
        string Sha512(string input);
    }
}
