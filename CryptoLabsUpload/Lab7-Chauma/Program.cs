using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ChaumBlindSignatureApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("🔏 Слепая подпись Чаума (RSA-based)");

            var chaum = new ChaumBlindSignature();
            string folderPath = "signature_data";
            Directory.CreateDirectory(folderPath);

            while (true)
            {
                Console.WriteLine("\nМеню:");
                Console.WriteLine("1. Сгенерировать ключи");
                Console.WriteLine("2. Ослепить сообщение");
                Console.WriteLine("3. Подписать слепое сообщение");
                Console.WriteLine("4. Снять слепоту с подписи");
                Console.WriteLine("5. Проверить подпись");
                Console.WriteLine("6. Выход");
                Console.Write("Выберите действие: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        // Генерация ключей
                        chaum.GenerateKeys(2048);
                        File.WriteAllText($"{folderPath}/public_key.txt", $"{chaum.N}\n{chaum.E}");
                        File.WriteAllText($"{folderPath}/private_key.txt", chaum.D.ToString());
                        Console.WriteLine("Ключи сгенерированы и сохранены");
                        break;

                    case "2":
                        // Ослепление сообщения
                        Console.Write("Введите сообщение (128 hex символов): ");
                        string messageHex = Console.ReadLine();
                        
                        if (messageHex.Length != 128 || !IsHex(messageHex))
                        {
                            Console.WriteLine("Некорректный ввод. Нужно 128 hex символов");
                            break;
                        }

                        BigInteger message = BigInteger.Parse("0" + messageHex, System.Globalization.NumberStyles.HexNumber);
                        var (blinded, k) = chaum.BlindMessage(message);
                        
                        File.WriteAllText($"{folderPath}/blinded_message.txt", blinded.ToString());
                        File.WriteAllText($"{folderPath}/blinding_factor.txt", k.ToString());
                        File.WriteAllText($"{folderPath}/original_message.txt", message.ToString());
                        
                        Console.WriteLine($"Сообщение ослеплено. Blinding factor сохранен");
                        break;

                    case "3":
                        // Подпись слепого сообщения
                        if (!File.Exists($"{folderPath}/blinded_message.txt"))
                        {
                            Console.WriteLine("Нет ослепленного сообщения");
                            break;
                        }

                        BigInteger blindedMsg = BigInteger.Parse(File.ReadAllText($"{folderPath}/blinded_message.txt"));
                        BigInteger signature = chaum.SignBlinded(blindedMsg);
                        
                        File.WriteAllText($"{folderPath}/blinded_signature.txt", signature.ToString());
                        Console.WriteLine("Слепое сообщение подписано");
                        break;

                    case "4":
                        // Снятие слепоты
                        if (!File.Exists($"{folderPath}/blinded_signature.txt") || 
                            !File.Exists($"{folderPath}/blinding_factor.txt"))
                        {
                            Console.WriteLine("Не хватает данных для снятия слепоты");
                            break;
                        }

                        BigInteger blindedSig = BigInteger.Parse(File.ReadAllText($"{folderPath}/blinded_signature.txt"));
                        BigInteger kFactor = BigInteger.Parse(File.ReadAllText($"{folderPath}/blinding_factor.txt"));
                        BigInteger finalSig = chaum.UnblindSignature(blindedSig, kFactor);
                        
                        File.WriteAllText($"{folderPath}/final_signature.txt", finalSig.ToString());
                        Console.WriteLine("Слепота снята, подпись готова");
                        break;

                    case "5":
                        // Проверка подписи
                        if (!File.Exists($"{folderPath}/original_message.txt") || 
                            !File.Exists($"{folderPath}/final_signature.txt"))
                        {
                            Console.WriteLine("Не хватает данных для проверки");
                            break;
                        }

                        BigInteger originalMsg = BigInteger.Parse(File.ReadAllText($"{folderPath}/original_message.txt"));
                        BigInteger finalSignature = BigInteger.Parse(File.ReadAllText($"{folderPath}/final_signature.txt"));
                        bool isValid = chaum.Verify(originalMsg, finalSignature);
                        
                        Console.WriteLine($"\n{(isValid ? "Подпись верна" : "Подпись недействительна")}");
                        break;

                    case "6":
                        return;

                    default:
                        Console.WriteLine("Неверный выбор");
                        break;
                }
            }
        }

        static bool IsHex(string input)
        {
            foreach (char c in input)
            {
                if (!Uri.IsHexDigit(c))
                    return false;
            }
            return true;
        }
    }

    public class ChaumBlindSignature
    {
        public BigInteger N { get; private set; }
        public BigInteger E { get; private set; }
        public BigInteger D { get; private set; }

        public void GenerateKeys(int keySize = 2048)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);
            var parameters = rsa.ExportParameters(true);
            
            N = new BigInteger(parameters.Modulus.Reverse().Concat(new byte[] { 0 }).ToArray());
            E = new BigInteger(parameters.Exponent.Reverse().Concat(new byte[] { 0 }).ToArray());
            D = new BigInteger(parameters.D.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        public (BigInteger blindedMsg, BigInteger k) BlindMessage(BigInteger message)
        {
            if (N == 0 || E == 0)
                throw new InvalidOperationException("Ключи не инициализированы");

            if (message >= N)
                throw new ArgumentException("Сообщение слишком большое");

            BigInteger k;
            var rng = RandomNumberGenerator.Create();
            do {
                k = RandomInRange(N - 1, rng);
            } while (BigInteger.GreatestCommonDivisor(k, N) != 1);

            BigInteger blinded = (message * BigInteger.ModPow(k, E, N)) % N;
            return (blinded, k);
        }

        public BigInteger SignBlinded(BigInteger blindedMsg)
        {
            if (D == 0)
                throw new InvalidOperationException("Приватный ключ не установлен");
            
            return BigInteger.ModPow(blindedMsg, D, N);
        }

        public BigInteger UnblindSignature(BigInteger blindedSig, BigInteger k)
        {
            BigInteger kInv = ModInverse(k, N);
            return (blindedSig * kInv) % N;
        }

        public bool Verify(BigInteger message, BigInteger signature)
        {
            return message == BigInteger.ModPow(signature, E, N);
        }

        private BigInteger RandomInRange(BigInteger max, RandomNumberGenerator rng)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do {
                rng.GetBytes(bytes);
                result = new BigInteger(bytes);
            } while (result <= 0 || result >= max);
            return result;
        }

        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 1) return 0;
            BigInteger m0 = m, y = 0, x = 1;
            while (a > 1)
            {
                BigInteger q = a / m;
                (a, m) = (m, a % m);
                (x, y) = (y, x - q * y);
            }
            return x < 0 ? x + m0 : x;
        }
    }
}