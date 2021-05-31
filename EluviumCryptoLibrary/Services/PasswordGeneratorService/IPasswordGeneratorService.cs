namespace EluviumCryptoLibrary.Services.PasswordGeneratorService
{
    public interface IPasswordGeneratorService
    {
        string GeneratePassword(int length, bool lowercase, bool uppercase, bool number, bool character, bool special);
    }
}
