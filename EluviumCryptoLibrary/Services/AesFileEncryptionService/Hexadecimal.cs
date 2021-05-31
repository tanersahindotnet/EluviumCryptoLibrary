using System.Linq;

namespace EluviumCore.Services.EncryptionService
{
    public static class Hexadecimal
    {

        public static string ToHexString(byte[] byteArray)
        {
            if (byteArray == null || byteArray.Length <= 0)
                return null;

            return string.Concat(byteArray.Select(b => b.ToString("X2")));
        }
    }
}