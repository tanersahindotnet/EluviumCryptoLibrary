using System;
using System.IO;
using System.Security.Cryptography;

namespace EluviumCore.Services.EncryptionService
{
    public abstract class AesBase
    {
        protected AesBase(){}
        #region events

        public event EventHandlers.OnEncryptionMessageHandler OnEncryptionMessage;

        public event EventHandlers.OnDecryptionMessageHandler OnDecryptionMessage;

        public event EventHandlers.OnEncryptionProgressHandler OnEncryptionProgress;

        public event EventHandlers.OnDecryptionProgressHandler OnDecryptionProgress;

        #endregion events

        #region fields

        private byte[] _key;
        private byte[] _iv;

        #endregion fields

        #region constructors

        internal AesBase(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        #endregion constructors

        #region internal methods

        internal AesEncryptionResult EncryptWithFileStream(string sourceFilePath, string encryptedFilePath, byte[] key = null, byte[] iv = null, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7, bool deleteSourceFile = false, int kBbufferSize = 4)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = $"FileNotFound \"{sourceFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = "EncryptedFilePathError"
                };
            }

            var destinationDirectory = Path.GetDirectoryName(encryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = $"DestinationDirectoryNotFound \"{destinationDirectory}\"."
                };
            }

            _key = key ?? _key;
            _iv = iv ?? _iv;

            bool pathsEqual = encryptedFilePath.Equals(sourceFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    if (_key == null)
                    {
                        aesManaged.GenerateKey();
                        _key = aesManaged.Key;
                    }
                    else
                    {
                        if (aesManaged.ValidKeySize(_key.Length * 8))
                            aesManaged.Key = _key;
                        else
                        {
                            return new AesEncryptionResult()
                            {
                                Success = false,
                                Message = $"InvalidKeySizeError ({_key.Length * 8})."
                            };
                        }
                    }

                    if (_iv == null || _iv.Length == 0)
                    {
                        aesManaged.GenerateIV();
                        _iv = aesManaged.IV;
                    }
                    else
                        aesManaged.IV = _iv;

                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

                    using (var encryptor = aesManaged.CreateEncryptor(_key, _iv))
                    {
                        using (var sourceFs = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            //sourceFs.Seek(0, SeekOrigin.Begin);
                            using (var encryptedFs = File.Open((pathsEqual ? encryptedFilePath + "_tmpcrypt" : encryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                //encryptedFs.Seek(headerOffset, SeekOrigin.Begin);
                                using (var cs = new CryptoStream(encryptedFs, encryptor, CryptoStreamMode.Write))
                                {
                                    //plain.CopyTo(cs);

                                    var buffer = new byte[kBbufferSize * 1024];
                                    int read;
                                    int percentageDone = 0;

                                    while ((read = sourceFs.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        cs.Write(buffer, 0, read);

                                        var tmpPercentageDone = (int)(sourceFs.Position * 100 / sourceFs.Length);

                                        if (tmpPercentageDone != percentageDone)
                                        {
                                            percentageDone = tmpPercentageDone;

                                            RaiseOnEncryptionProgress(percentageDone, (percentageDone != 100 ? $"Encrypting ({percentageDone}%)..." : $"Encrypted ({percentageDone}%)."));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid errors while trying to delete the file below
                    File.Delete(sourceFilePath);
                    File.Move(encryptedFilePath + "_tmpcrypt", encryptedFilePath);
                }

                if (deleteSourceFile && !pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(sourceFilePath); // set "Normal" FileAttributes to avoid errors while trying to delete the file below
                    File.Delete(sourceFilePath);
                }

                var message = "FileEncryptSuccess";
                message += (deleteSourceFile && !pathsEqual ? "\nFileDeleted" : "");

                return new AesEncryptionResult
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    Iv = _iv,
                    AesCipherMode = (AesCipherMode)cipherMode,
                    PaddingMode = paddingMode
                };
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = $"ExceptionError\n{ex}"
                };
            }
        }

        internal AesDecryptionResult DecryptWithFileStream(string encryptedFilePath, string decryptedFilePath, byte[] key, byte[] iv, CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7, bool deleteEncryptedFile = false, int kBbufferSize = 4, long startPosition = 0, long endPosition = 0)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = $"EncryptedFileNotFound \"{encryptedFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "DecryptedFilePathError"
                };
            }

            var destinationDirectory = Path.GetDirectoryName(decryptedFilePath);

            if (!Directory.Exists(destinationDirectory))
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = $"DestinationDirectoryNotFound \"{destinationDirectory}\"."
                };
            }

            _key = key ?? _key;
            _iv = iv ?? _iv;

            if (_key == null)
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "NullKeyError"
                };
            }

            if (_iv == null)
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "NullIVError"
                };
            }

            if (endPosition < startPosition)
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "EndPositionLessThanStartError"
                };
            }

            bool pathsEqual = decryptedFilePath.Equals(encryptedFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using (var aesManaged = new AesManaged())
                {
                    aesManaged.Key = _key;
                    aesManaged.IV = _iv;
                    aesManaged.Mode = cipherMode;
                    aesManaged.Padding = paddingMode;

                    using (var decryptedFs = File.Open((pathsEqual ? decryptedFilePath + "_tmpdecrypt" : decryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        //decryptedFs.Seek(0, SeekOrigin.Begin);
                        using (var encryptedFs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            //encryptedFs.Seek(headerOffset, SeekOrigin.Begin);
                            encryptedFs.Position = startPosition;
                            using (var decryptor = aesManaged.CreateDecryptor(_key, _iv))
                            {
                                using (var cs = new CryptoStream(decryptedFs, decryptor, CryptoStreamMode.Write))
                                {
                                    //encrypted.CopyTo(cs);

                                    var buffer = new byte[kBbufferSize * 1024];
                                    long totalBytesToRead = ((endPosition == 0 ? encryptedFs.Length : endPosition) - startPosition);
                                    long totalBytesNotRead = totalBytesToRead;
                                    long totalBytesRead = 0;
                                    int percentageDone = 0;

                                    while (totalBytesNotRead > 0)
                                    {
                                        int bytesRead = encryptedFs.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                                        if (bytesRead > 0)
                                        {
                                            cs.Write(buffer, 0, bytesRead);

                                            totalBytesRead += bytesRead;
                                            totalBytesNotRead -= bytesRead;
                                            var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                                            if (tmpPercentageDone != percentageDone)
                                            {
                                                percentageDone = tmpPercentageDone;

                                                RaiseOnDecryptionProgress(percentageDone, (percentageDone != 100 ? $"Decrypting ({percentageDone}%)..." : $"Decrypted ({percentageDone}%)."));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid errors while trying to delete the file below
                    File.Delete(encryptedFilePath);
                    File.Move(decryptedFilePath + "_tmpdecrypt", decryptedFilePath);
                }

                if (deleteEncryptedFile && !pathsEqual)
                {
                    CommonMethods.ClearFileAttributes(encryptedFilePath); // set "Normal" FileAttributes to avoid errors while trying to delete the file below
                    File.Delete(encryptedFilePath);
                }

                var message = "FileDecryptSuccess";
                message += (deleteEncryptedFile && !pathsEqual ? "\nFileDeleted" : "");

                return new AesDecryptionResult()
                {
                    Success = true,
                    Message = message,
                    Key = _key,
                    Iv = _iv,
                    AesCipherMode = (AesCipherMode)cipherMode,
                    PaddingMode = paddingMode
                };
            }
            catch (Exception ex)
            {
                return new AesDecryptionResult()
                {
                    Success = false,
                    Message = $"ExceptionError\n{ex}"
                };
            }
        }

        #endregion internal methods

        #region private methods

        internal void RaiseOnEncryptionMessage(string message)
        {
            OnEncryptionMessage?.Invoke(message);
        }

        internal void RaiseOnEncryptionProgress(int percentageDone, string message)
        {
            OnEncryptionProgress?.Invoke(percentageDone, message);
        }

        internal void RaiseOnDecryptionProgress(int percentageDone, string message)
        {
            OnDecryptionProgress?.Invoke(percentageDone, message);
        }

        #endregion private methods
    }
}