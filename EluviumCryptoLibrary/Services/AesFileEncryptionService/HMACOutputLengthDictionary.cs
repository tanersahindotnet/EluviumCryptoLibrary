using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace EluviumCore.Services.EncryptionService
{
    public sealed class HmacOutputLengthDictionary
    {
        private static readonly Lazy<HmacOutputLengthDictionary> LazyHmacOutputLengthDictionary = new Lazy<HmacOutputLengthDictionary>(() => new HmacOutputLengthDictionary());

        private readonly IDictionary<HmacAlgorithm, int> _dicHmacAlgorithmOutputLengths = new ConcurrentDictionary<HmacAlgorithm, int>()
        {
            [HmacAlgorithm.Hmacmd5] = 128,
            [HmacAlgorithm.Hmacsha1] = 160,
            [HmacAlgorithm.Hmacsha256] = 256,
            [HmacAlgorithm.Hmacsha384] = 384,
            [HmacAlgorithm.Hmacsha512] = 512
        };

        public static HmacOutputLengthDictionary Instance => LazyHmacOutputLengthDictionary.Value;

        private HmacOutputLengthDictionary()
        {
        }

        private int GetOutputLength(HmacAlgorithm key)
        {
            if (!_dicHmacAlgorithmOutputLengths.TryGetValue(key, out var outputBytesLength))
                outputBytesLength = 0;

            return outputBytesLength;
        }

        public int this[HmacAlgorithm key] => GetOutputLength(key);
    }
}