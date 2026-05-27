using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ShamirSecretSharingApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("Программа разделения секрета Шамира");

            while (true)
            {
                Console.WriteLine("\nМеню:");
                Console.WriteLine("1. Разделить секрет");
                Console.WriteLine("2. Восстановить секрет");
                Console.WriteLine("3. Выход");
                Console.Write("Выберите действие: ");

                string choice = Console.ReadLine();
                switch (choice)
                {
                    case "1":
                        SplitSecret();
                        break;
                    case "2":
                        ReconstructSecret();
                        break;
                    case "3":
                        return;
                    default:
                        Console.WriteLine("Неверный ввод!");
                        break;
                }
            }
        }

        /// Метод для разделения секрета на доли
        static void SplitSecret()
        {
            try
            {
                Console.Write("\nВведите имя секрета: ");
                string secretName = Console.ReadLine();

                Console.Write("Введите секрет (HEX строка): ");
                string hexSecret = Console.ReadLine();

                // Преобразуем HEX строку в байты
                byte[] bytes = new byte[hexSecret.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(hexSecret.Substring(i * 2, 2), 16);
                }

                Console.Write("Введите количество долей (n): ");
                int n = int.Parse(Console.ReadLine());

                Console.Write("Введите пороговое значение (k): ");
                int k = int.Parse(Console.ReadLine());

                // Генерируем простое число p > секрета
                BigInteger secretValue = new BigInteger(bytes.Reverse().Concat(new byte[] { 0 }).ToArray());
                BigInteger p = GeneratePrimeGreaterThan(secretValue);

                // Разделяем секрет
                var shares = ShamirSecretSharing.SplitSecret(secretValue, n, k, p);

                // Создаем папку для сохранения
                string folderPath = "secrets";
                Directory.CreateDirectory(folderPath);

                // Сохраняем доли в файлы
                for (int i = 0; i < shares.Length; i++)
                {
                    string shareFileName = $"{folderPath}/{secretName}_share_{i + 1}.txt";
                    File.WriteAllText(shareFileName, $"{shares[i].x}\n{shares[i].y}", Encoding.UTF8);
                    Console.WriteLine($"Создана доля {i + 1} в файле {shareFileName}");
                }

                // Сохраняем параметры
                string paramsFileName = $"{folderPath}/{secretName}_params.txt";
                File.WriteAllText(paramsFileName, $"{n}\n{k}\n{p}", Encoding.UTF8);
                Console.WriteLine($"Параметры сохранены в {paramsFileName}");

                Console.WriteLine("Секрет успешно разделен!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }

        /// Метод для восстановления секрета из долей
        static void ReconstructSecret()
        {
            try
            {
                Console.Write("\nВведите имя секрета: ");
                string secretName = Console.ReadLine();

                string folderPath = "secrets";

                // Читаем параметры
                string paramsFileName = $"{folderPath}/{secretName}_params.txt";
                if (!File.Exists(paramsFileName))
                {
                    Console.WriteLine("Файл параметров не найден!");
                    return;
                }

                string[] paramsContent = File.ReadAllLines(paramsFileName);
                int n = int.Parse(paramsContent[0]);
                int k = int.Parse(paramsContent[1]);
                BigInteger p = BigInteger.Parse(paramsContent[2]);

                Console.WriteLine($"Требуется {k} из {n} долей для восстановления");

                // Запрашиваем доли
                var shares = new (BigInteger x, BigInteger y)[k];
                for (int i = 0; i < k; i++)
                {
                    Console.Write($"Введите номер доли {i + 1}: ");
                    int shareNum = int.Parse(Console.ReadLine());

                    string shareFileName = $"{folderPath}/{secretName}_share_{shareNum}.txt";
                    if (!File.Exists(shareFileName))
                    {
                        Console.WriteLine($"Файл доли {shareNum} не найден!");
                        return;
                    }

                    string[] shareContent = File.ReadAllLines(shareFileName);
                    shares[i] = (BigInteger.Parse(shareContent[0]), BigInteger.Parse(shareContent[1]));
                }

                // Восстанавливаем секрет
                BigInteger secret = ShamirSecretSharing.ReconstructSecret(shares, p);

                // Преобразуем в байты с учетом порядка
                byte[] bytes = secret.ToByteArray();

                // Удаляем возможный знаковый байт (0x00 для положительных чисел)
                if (bytes.Length > 1 && bytes[bytes.Length - 1] == 0)
                {
                    bytes = bytes.Take(bytes.Length - 1).ToArray();
                }

                // Переворачиваем порядок байт (little-endian → big-endian)
                Array.Reverse(bytes);

                // Преобразуем в HEX строку
                StringBuilder hex = new StringBuilder(bytes.Length * 2);
                foreach (byte b in bytes)
                {
                    hex.AppendFormat("{0:X2}", b);
                }
                string hexSecret = hex.ToString();

                Console.WriteLine($"\nВосстановленный секрет: {hexSecret}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }

        /// Генерирует простое число больше заданного значения
        static BigInteger GeneratePrimeGreaterThan(BigInteger minValue)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                BigInteger candidate = minValue + 1;
                while (true)
                {
                    if (candidate.IsProbablyPrime())
                        return candidate;
                    candidate++;
                }
            }
        }
    }

    /// Класс для реализации протокола Шамира
    public static class ShamirSecretSharing
    {
        /// Разделяет секрет на доли
        public static (BigInteger x, BigInteger y)[] SplitSecret(BigInteger secret, int n, int k, BigInteger prime)
        {
            if (k > n)
                throw new ArgumentException("k должно быть меньше или равно n");

            using (var rng = RandomNumberGenerator.Create())
            {
                // Генерируем случайные коэффициенты полинома
                BigInteger[] coefficients = new BigInteger[k - 1];
                for (int i = 0; i < k - 1; i++)
                {
                    coefficients[i] = RandomInRange(prime - 1, rng) + 1;
                }

                // Вычисляем значения полинома в точках 1..n
                var shares = new (BigInteger x, BigInteger y)[n];
                for (int i = 0; i < n; i++)
                {
                    BigInteger x = i + 1;
                    BigInteger y = secret;

                    // Вычисляем f(x) = secret + a1*x + a2*x² + ... + a_{k-1}*x^{k-1}
                    for (int pow = 1; pow < k; pow++)
                    {
                        y += coefficients[pow - 1] * BigInteger.Pow(x, pow);
                    }

                    shares[i] = (x, y % prime);
                }

                return shares;
            }
        }

        /// Восстанавливает секрет из долей
        public static BigInteger ReconstructSecret((BigInteger x, BigInteger y)[] shares, BigInteger prime)
        {
            BigInteger secret = 0;
            
            for (int i = 0; i < shares.Length; i++)
            {
                // Вычисляем коэффициент Лагранжа L_i(0)
                BigInteger lagrange = 1;
                for (int j = 0; j < shares.Length; j++)
                {
                    if (i != j)
                    {
                        BigInteger x_i = shares[i].x;
                        BigInteger x_j = shares[j].x;
                        
                        // L_i(0) = ∏ (0 - x_j)/(x_i - x_j) = ∏ (-x_j)/(x_i - x_j)
                        BigInteger term = (-x_j + prime) % prime;  // Обработаем отрицательные x_j
                        BigInteger denominator = (x_i - x_j + prime) % prime;  // То же для знаменателя

                        // Убедимся, что знаменатель не равен 0
                        if (denominator == 0)
                            throw new InvalidOperationException("Делитель равен нулю! Проверьте значения точек.");

                        // Используем модульное обращение для деления по модулю
                        BigInteger inverse = ModInverse(denominator, prime);
                        lagrange = lagrange * term % prime * inverse % prime;
                    }
                }

                // Добавляем вклад текущей доли
                secret = (secret + shares[i].y * lagrange) % prime;
            }

            // Корректируем секрет на случай отрицательного результата
            return secret < 0 ? secret + prime : secret;
        }


        /// Вычисляет модульный обратный элемент
        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            return x < 0 ? x + m0 : x;
        }

        /// Генерирует случайное число в диапазоне [0, max-1]
        private static BigInteger RandomInRange(BigInteger max, RandomNumberGenerator rng)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                rng.GetBytes(bytes);
                result = new BigInteger(bytes) % max;
            } while (result < 0);
            return result;
        }
    }

    /// Расширения для BigInteger
    public static class BigIntegerExtensions
    {
        /// Проверяет, является ли число простым (тест Миллера-Рабина)
        public static bool IsProbablyPrime(this BigInteger value, int iterations = 10)
        {
            if (value < 2) return false;
            if (value == 2) return true;
            if (value % 2 == 0) return false;

            BigInteger d = value - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[value.ToByteArray().Length];
                for (int i = 0; i < iterations; i++)
                {
                    BigInteger a;
                    do
                    {
                        rng.GetBytes(bytes);
                        a = new BigInteger(bytes);
                    } while (a < 2 || a >= value - 2);

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
            }

            return true;
        }
    }
}