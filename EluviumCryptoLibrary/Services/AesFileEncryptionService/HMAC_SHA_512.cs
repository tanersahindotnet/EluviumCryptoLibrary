namespace EluviumCore.Services.EncryptionService
{
    public class HmacSha512 : HmacBase
    {
        /// <summary>
        /// Computes the HMACSHA512 of an input file using a key.
        /// </summary>
        /// <param name="filePathToComputeHmac">The input file path to compute the HMACSHA512.</param>
        /// <param name="key">The input key byte array. Leave empty or pass null to auto-generate a secure random key. The key will be present in the HMACHashResult return.</param>
        /// <param name="offset">The offset into the FileStream from which to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>HMACHashResult</returns>
        public HmacHashResult ComputeFileHmac(string filePathToComputeHmac, byte[] key = null, long offset = 0, long count = 0)
        {
            return ComputeFileHmac(HmacAlgorithm.Hmacsha512, filePathToComputeHmac, key, offset, count);
        }
    }
}