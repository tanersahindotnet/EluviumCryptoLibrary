using System.Security.Cryptography;

namespace EluviumCore.Services.EncryptionService
{
    public class AesEncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public byte[] Key { get; set; }
        public byte[] Iv { get; set; }
        public AesCipherMode AesCipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
        public byte[] Salt { get; set; }
        public byte[] AuthenticationKey { get; set; }
        public byte[] Tag { get; set; }
    }
}