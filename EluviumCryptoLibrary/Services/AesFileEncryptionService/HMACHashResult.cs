namespace EluviumCore.Services.EncryptionService
{
    public class HmacHashResult : GenericHashResult
    {
        public byte[] Key { get; set; }
    }
}