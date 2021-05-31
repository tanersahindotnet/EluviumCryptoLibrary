namespace EluviumCryptoLibrary.Services.AesStringEncryptionService
{
    public interface IAesStringEncryptionService
    {
        string EncryptString(string plainText, string passPhrase);
        string DecryptString(string encrypted, string passPhrase);
    }
}
