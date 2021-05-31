namespace EluviumCore.Services.EncryptionService
{
    public class GenericHashResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string HashString { get; set; }
        public byte[] HashBytes { get; set; }
    }
}