using System;
using System.Security.Cryptography;

namespace EluviumCryptoLibrary.Services.DigitalSignatureService
{
    public interface IDigitalSignatureService
    {
        Tuple<RSAParameters, RSAParameters> CreatePublicAndPrivateKeyPair();
        byte[] Sign(string message, RSAParameters privateAndPublicKeys);
        bool Verify(string message, byte[] signature, RSAParameters publicKeyOnly);
    }
}
