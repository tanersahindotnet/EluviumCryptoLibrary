using System.Threading.Tasks;

namespace EluviumCryptoLibrary.Services.PasswordAdvisorService
{
    public interface IPasswordAdvisorService
    {
        Task<(bool passwordCompromised, int breachCount)> CheckPasswordAsync(string password);
        PasswordScoreEnum CheckStrength(string password);
    }
}
