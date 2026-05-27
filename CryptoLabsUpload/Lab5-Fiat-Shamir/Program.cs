using System;
using System.Numerics;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Linq;

namespace FiatShamirParallelAuth
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("🔐 Параллельная схема аутентификации Фиата-Шамира");
            
            while (true)
            {
                Console.WriteLine("\nМеню:");
                Console.WriteLine("1. Создать и сохранить секретные ключи");
                Console.WriteLine("2. Пройти аутентификацию (Prover)");
                Console.WriteLine("3. Проверить аутентификацию (Verifier)");
                Console.WriteLine("4. Выход");
                Console.Write("Выберите действие: ");

                string choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        GenerateAndSaveKeys();
                        break;
                    case "2":
                        PerformAuthentication();
                        break;
                    case "3":
                        VerifyAuthentication();
                        break;
                    case "4":
                        return;
                    default:
                        Console.WriteLine("Неверный ввод!");
                        break;
                }
            }
        }

        /// Генерация и сохранение ключей для протокола
        static void GenerateAndSaveKeys()
        {
            Console.Write("\nВведите имя для ключей: ");
            string keysName = Console.ReadLine();

            Console.Write("Введите количество секретов (k): ");
            int k = int.Parse(Console.ReadLine());

            // Создаем экземпляр протокола
            var protocol = new FiatShamirProtocol();
            
            // Генерируем ключи
            protocol.GenerateKeys(k);

            // Создаем папку для хранения ключей
            string dir = "keys";
            Directory.CreateDirectory(dir);

            // Сохраняем секретные ключи
            for (int i = 0; i < k; i++)
            {
                // Каждый секретный ключ сохраняем в отдельный файл в HEX-формате
                File.WriteAllText($"{dir}/{keysName}_secret_{i}.txt", protocol.Secrets[i].ToString("X"));
                // Сохраняем соответствующие публичные ключи
                File.WriteAllText($"{dir}/{keysName}_public_{i}.txt", protocol.PublicKeys[i].ToString("X"));
            }

            // Сохраняем модуль n
            File.WriteAllText($"{dir}/{keysName}_n.txt", protocol.N.ToString("X"));
            
            Console.WriteLine($"✅ Ключи успешно сохранены в папке {dir}/");
            Console.WriteLine($"Модуль n (общий для всех ключей): {protocol.N.ToString("X")}");
        }

        /// Процесс аутентификации (сторона Prover)
        static void PerformAuthentication()
        {
            Console.Write("\nВведите имя ключей: ");
            string keysName = Console.ReadLine();

            string dir = "keys";
            
            try
            {
                // Загружаем все файлы с секретными ключами
                var secretFiles = Directory.GetFiles(dir, $"{keysName}_secret_*.txt");
                
                // Сортируем файлы по порядку и загружаем секреты
                BigInteger[] secrets = secretFiles
                    .OrderBy(f => int.Parse(Path.GetFileNameWithoutExtension(f).Split('_').Last()))
                    .Select(f => BigInteger.Parse(File.ReadAllText(f), System.Globalization.NumberStyles.HexNumber))
                    .ToArray();

                // Загружаем модуль n
                BigInteger n = BigInteger.Parse(File.ReadAllText($"{dir}/{keysName}_n.txt"), 
                    System.Globalization.NumberStyles.HexNumber);

                var protocol = new FiatShamirProtocol();
                
                // Шаг 1: Prover выбирает случайное число r
                using (var rng = RandomNumberGenerator.Create())
                {
                    // Генерируем случайное r в диапазоне [1, n-1]
                    BigInteger r = protocol.RandomInRange(n, rng);
                    
                    // Вычисляем x = r² mod n
                    BigInteger x = (r * r) % n;

                    Console.WriteLine($"\nШаг 1: Сгенерировано случайное число r");
                    Console.WriteLine($"Отправляем verifier'у x = r² mod n = {x.ToString("X")}");

                    // Шаг 2: Verifier генерирует случайные биты e_i (0 или 1 для каждого секрета)
                    bool[] e = new bool[secrets.Length];
                    Random rand = new Random();
                    for (int i = 0; i < e.Length; i++)
                    {
                        e[i] = rand.Next(0, 2) == 1;
                    }

                    Console.WriteLine("\nШаг 2: Verifier отправляет биты:");
                    for (int i = 0; i < e.Length; i++)
                    {
                        Console.WriteLine($"e_{i} = {(e[i] ? 1 : 0)}");
                    }

                    // Шаг 3: Prover вычисляет y = r * (произведение s_i для которых e_i=1) mod n
                    BigInteger product = 1;
                    for (int i = 0; i < secrets.Length; i++)
                    {
                        if (e[i])
                        {
                            product = (product * secrets[i]) % n;
                        }
                    }
                    BigInteger y = (r * product) % n;

                    Console.WriteLine("\nШаг 3: Вычисляем y = r * (∏ s_i^e_i) mod n");
                    Console.WriteLine($"Отправляем verifier'у y = {y.ToString("X")}");

                    // Сохраняем данные аутентификации для последующей проверки
                    File.WriteAllText($"{dir}/auth_x.txt", x.ToString("X"));
                    File.WriteAllText($"{dir}/auth_y.txt", y.ToString("X"));
                    File.WriteAllLines($"{dir}/auth_e.txt", e.Select(b => b ? "1" : "0"));
                    
                    Console.WriteLine("\n✅ Аутентификация выполнена. Данные сохранены для проверки.");
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("❌ Ошибка: Файлы ключей не найдены! Сначала создайте ключи.");
            }
        }

        /// Проверка аутентификации (сторона Verifier)
        static void VerifyAuthentication()
        {
            Console.Write("\nВведите имя ключей: ");
            string keysName = Console.ReadLine();

            string dir = "keys";
            
            try
            {
                // Загружаем публичные ключи
                var publicFiles = Directory.GetFiles(dir, $"{keysName}_public_*.txt");
                BigInteger[] publicKeys = publicFiles
                    .OrderBy(f => int.Parse(Path.GetFileNameWithoutExtension(f).Split('_').Last()))
                    .Select(f => BigInteger.Parse(File.ReadAllText(f), System.Globalization.NumberStyles.HexNumber))
                    .ToArray();

                // Загружаем модуль n
                BigInteger n = BigInteger.Parse(File.ReadAllText($"{dir}/{keysName}_n.txt"), 
                    System.Globalization.NumberStyles.HexNumber);

                // Загружаем данные аутентификации
                BigInteger x = BigInteger.Parse(File.ReadAllText($"{dir}/auth_x.txt"), 
                    System.Globalization.NumberStyles.HexNumber);
                BigInteger y = BigInteger.Parse(File.ReadAllText($"{dir}/auth_y.txt"), 
                    System.Globalization.NumberStyles.HexNumber);
                bool[] e = File.ReadAllLines($"{dir}/auth_e.txt").Select(s => s == "1").ToArray();

                Console.WriteLine("\nПроверка аутентификации:");
                Console.WriteLine($"x = {x.ToString("X")}");
                Console.WriteLine($"y = {y.ToString("X")}");
                Console.WriteLine("Биты e: " + string.Join(", ", e.Select(b => b ? 1 : 0)));

                // Вычисляем правую часть уравнения проверки: x * (∏ v_i^e_i) mod n
                BigInteger product = 1;
                for (int i = 0; i < publicKeys.Length; i++)
                {
                    if (e[i])
                    {
                        product = (product * publicKeys[i]) % n;
                    }
                }
                BigInteger rightSide = (x * product) % n;
                
                // Левая часть уравнения проверки: y² mod n
                BigInteger leftSide = (y * y) % n;

                Console.WriteLine($"\ny² mod n = {leftSide.ToString("X")}");
                Console.WriteLine($"x * (∏ v_i^e_i) mod n = {rightSide.ToString("X")}");

                // Проверяем равенство y² ≡ x * (∏ v_i^e_i) mod n
                if (leftSide == rightSide)
                {
                    Console.WriteLine("\n✅ Аутентификация успешна! Доказательство верно.");
                }
                else
                {
                    Console.WriteLine("\n❌ Аутентификация не удалась! Доказательство неверно.");
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("❌ Ошибка: Не найдены необходимые файлы ключей или данных аутентификации!");
            }
        }
    }

    /// Класс, реализующий протокол Фиата-Шамира
    public class FiatShamirProtocol
    {
        /// Секретные ключи (s₁, s₂, ..., sₖ)
        public BigInteger[] Secrets { get; private set; }

        /// Публичные ключи (v₁, v₂, ..., vₖ), где v_i = s_i² mod n
        public BigInteger[] PublicKeys { get; private set; }

        /// Модуль n = p * q (как в RSA)
        public BigInteger N { get; private set; }

        /// Генерация ключей для протокола
        public void GenerateKeys(int k, int bitSize = 256)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                // Генерируем два больших простых числа
                BigInteger p = GeneratePrime(bitSize, rng);
                BigInteger q = GeneratePrime(bitSize, rng);
                
                // Вычисляем модуль n = p * q
                N = p * q;

                // Инициализируем массивы для ключей
                Secrets = new BigInteger[k];
                PublicKeys = new BigInteger[k];

                // Генерируем k секретных ключей и соответствующих публичных ключей
                for (int i = 0; i < k; i++)
                {
                    // Секретный ключ - случайное число в диапазоне [1, n-1]
                    Secrets[i] = RandomInRange(N, rng);
                    
                    // Публичный ключ v_i = s_i² mod n
                    PublicKeys[i] = (Secrets[i] * Secrets[i]) % N;
                }
            }
        }

        /// Генерация случайного числа в диапазоне [1, max-1]
        public BigInteger RandomInRange(BigInteger max, RandomNumberGenerator rng)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                rng.GetBytes(bytes);
                result = new BigInteger(bytes) % max;
            } while (result <= 0); // Повторяем, пока не получим число > 0
            
            return result;
        }

        /// Генерация большого простого числа указанного размера
        private BigInteger GeneratePrime(int bitSize, RandomNumberGenerator rng)
        {
            while (true)
            {
                // Генерируем случайное число
                BigInteger number = RandomInRange(BigInteger.Pow(2, bitSize), rng);
                
                // Проверяем на простоту
                if (number.IsProbablyPrime())
                    return number;
            }
        }
    }

    /// Расширения для работы с BigInteger
    public static class BigIntegerExtensions
    {
        /// Тест Миллера-Рабина на простоту числа
        public static bool IsProbablyPrime(this BigInteger value, int iterations = 5)
        {
            // Обработка простых случаев
            if (value < 2) return false;
            if (value == 2) return true;
            if (value % 2 == 0) return false;

            // Раскладываем value-1 в виде d * 2^s
            BigInteger d = value - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            Random rnd = new Random();
            for (int i = 0; i < iterations; i++)
            {
                // Выбираем случайное основание a в диапазоне [2, value-2]
                BigInteger a = RandomInRange(2, value - 2, rnd);
                
                // x = a^d mod value
                BigInteger x = BigInteger.ModPow(a, d, value);
                
                if (x == 1 || x == value - 1)
                    continue;

                for (int j = 0; j < s - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }

                if (x != value - 1) return false;
            }
            return true;
        }

        /// Генерация случайного числа в диапазоне [min, max)
        private static BigInteger RandomInRange(BigInteger min, BigInteger max, Random rnd)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                rnd.NextBytes(bytes);
                result = new BigInteger(bytes);
            } while (result < min || result >= max);
            
            return result;
        }
        /// Генерация случайного числа в диапазоне [1, max-1]
        public BigInteger RandomInRange(BigInteger max, RandomNumberGenerator rng)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                rng.GetBytes(bytes);
                result = new BigInteger(bytes) % max;
            } while (result <= 0); // Повторяем, пока не получим число > 0
            
            return result;
        }
    }
}