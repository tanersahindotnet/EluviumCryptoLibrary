using System;
using System.Collections.Generic;

namespace EluviumCryptoLibrary.Services.PasswordGeneratorService
{
    public class PasswordGeneratorService : IPasswordGeneratorService
    {
        private readonly Random _random = new Random();
        public string GeneratePassword(int length, bool lowercase, bool uppercase, bool number, bool character, bool special)
        {
            var generated = "";
            var characterTypes = new List<string>
            {
                "abcdefghijklmnopqrstuvwxyz",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "0123456789",
                "@#$%",
                "{}[]()'`~,;:.<>"
            };
            var count = 0;
            for (var i = 0; i < length; i++)
            {
                if (!lowercase && count == 0) { count++; }
                if (!uppercase && count == 1) { count++; }
                if (!number && count == 2) { count++; }
                if (!character && count == 3) { count++; }
                if (!special && count == 4) { count++; }
                if (count == 5) { count = 0; }
                generated += GetRandomValue(characterTypes[count]);
                count++;
            }

            return generated;
        }
        private string GetRandomValue(string character)
        {
            return character[_random.Next(character.Length - 1)].ToString();
        }
    }
}
