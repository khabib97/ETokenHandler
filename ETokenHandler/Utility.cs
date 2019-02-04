using System;
using System.Text;
using System.Security.Cryptography;

namespace ETokenHandler
{
    internal class Utility
    {
        public static String SHA1(String data)
        {

            byte[] shaBytes;
            SHA1 sha1 = new SHA1CryptoServiceProvider();

            shaBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));

            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte shaByte in shaBytes)
            {
                var hex = shaByte.ToString("x2");
                stringBuilder.Append(hex);
            }
            return stringBuilder.ToString();
        }
    }
}