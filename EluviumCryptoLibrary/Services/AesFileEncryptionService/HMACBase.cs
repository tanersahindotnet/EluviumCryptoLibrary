using System;
using System.IO;
using System.Security.Cryptography;

namespace EluviumCore.Services.EncryptionService
{
    public abstract class HmacBase
    {
        public event EventHandlers.OnHashProgressHandler OnHashProgress;

        internal HmacHashResult ComputeFileHmac(HmacAlgorithm hmacAlgorithm, string filePathToComputeHmac, byte[] key = null,
            long offset = 0, long count = 0)
        {
            if (!File.Exists(filePathToComputeHmac))
            {
                return new HmacHashResult()
                {
                    Success = false,
                    Message = $"FileNotFound \"{filePathToComputeHmac}\"."
                };
            }

            if (key == null || key.Length == 0)
                key = CommonMethods.GenerateRandomBytes(HmacOutputLengthDictionary.Instance[hmacAlgorithm] / 8);

            HmacHashResult result;

            try
            {
                byte[] hash;

                using (var fStream = new FileStream(filePathToComputeHmac, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    //offset = (offset == 0 ? 0 : offset);
                    count = (count == 0 ? fStream.Length : count);
                    fStream.Position = offset;
                    byte[] buffer = new byte[(1024 * 4)];
                    long amount = (count - offset);

                    using (var hmac = (HMAC)CryptoConfig.CreateFromName(hmacAlgorithm.ToString()))
                    {
                        hmac.Key = key;
                        int percentageDone = 0;

                        while (amount > 0)
                        {
                            int bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                    hmac.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                else
                                    hmac.TransformFinalBlock(buffer, 0, bytesRead);

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                                }
                            }
                            else
                                throw new InvalidOperationException();
                        }

                        hash = hmac.Hash;
                    }
                }

                result = new HmacHashResult
                {
                    Success = true,
                    Message = "ComputeSuccess",
                    HashString = Hexadecimal.ToHexString(hash),
                    HashBytes = hash,
                    Key = key
                };
            }
            catch (Exception ex)
            {
                result = new HmacHashResult
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        internal void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}