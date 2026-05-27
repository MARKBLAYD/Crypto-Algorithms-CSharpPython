using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace OngShnorrShamirSecretChannel
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Реализация секретного канала Онга-Шнорра-Шамира");
            Console.WriteLine("================================================\n");

            // Предложение пользователю выбрать режим работы
            Console.Write("Вы хотите использовать учебный режим с пошаговым выполнением? (y/n): ");
            bool tutorialMode = Console.ReadLine().Trim().ToLower() == "y";

            if (!tutorialMode)
            {
                // Режим прямого шифрования/дешифрования без пошаговых объяснений
                Console.WriteLine("\nРежим прямого шифрования/дешифрования");
                Console.WriteLine("-------------------------------------");

                // Выбор действия пользователем
                Console.WriteLine("\nВыберите действие:");
                Console.WriteLine("1. Зашифровать сообщения (x, y) -> получить подпись (S1, S2)");
                Console.WriteLine("2. Расшифровать подпись (S1, S2) -> получить сообщения (x, y)");
                Console.Write("Ваш выбор (1 или 2): ");
                string choice = Console.ReadLine();

                if (choice == "1")
                {
                    // Блок шифрования: преобразование сообщений в подпись
                    Console.WriteLine("\nРежим шифрования (x,y -> S1,S2)");

                    // Генерация криптографических параметров
                    Console.WriteLine("\nГенерация параметров...");
                    BigInteger p = GeneratePrime(512); // 512-битное простое
                    BigInteger q = GeneratePrime(512); // 512-битное простое
                    BigInteger n = p * q;             // Модуль RSA

                    // Генерация секретного ключа k (взаимно простого с n)
                    BigInteger k;
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        do
                        {
                            k = GenerateRandomBigInteger(2, n - 1, rng);
                        } while (BigInteger.GreatestCommonDivisor(k, n) != 1);
                    }

                    // Ввод и валидация сообщений
                    BigInteger x, y;
                    Console.WriteLine($"\nВведите сообщения (должны быть в диапазоне 2-{n - 1} и взаимно просты с n)");

                    while (true)
                    {
                        x = ReadBigInteger("Введите публичное сообщение x: ");
                        y = ReadBigInteger("Введите приватное сообщение y: ");

                        // Проверка ограничений для x и y
                        bool valid = true;
                        if (x < 2 || x >= n)
                        {
                            Console.WriteLine($"ОШИБКА: x должно быть в диапазоне 2 ≤ x ≤ {n - 1}");
                            valid = false;
                        }
                        if (y < 2 || y >= n)
                        {
                            Console.WriteLine($"ОШИБКА: y должно быть в диапазоне 2 ≤ y ≤ {n - 1}");
                            valid = false;
                        }
                        if (valid && BigInteger.GreatestCommonDivisor(x, n) != 1)
                        {
                            Console.WriteLine("ОШИБКА: x должно быть взаимно просто с n");
                            valid = false;
                        }
                        if (valid && BigInteger.GreatestCommonDivisor(y, n) != 1)
                        {
                            Console.WriteLine("ОШИБКА: y должно быть взаимно просто с n");
                            valid = false;
                        }

                        if (valid) break;
                        Console.WriteLine("Пожалуйста, введите корректные значения.");
                    }

                    // Вычисление подписи по схеме OSS
                    BigInteger invY = ModInverse(y, n);            // y^{-1} mod n
                    BigInteger term1 = (x * invY) % n;            // x * y^{-1}
                    BigInteger inv2 = ModInverse(2, n);           // 2^{-1} mod n
                    BigInteger S1 = (term1 + y) * inv2 % n;       // Первый компонент подписи
                    BigInteger S2 = k * (term1 - y) % n * inv2 % n; // Второй компонент подписи

                    // Вывод результатов и параметров
                    Console.WriteLine("\nШифрование выполнено успешно!");
                    Console.WriteLine("\nПараметры шифрования (сохраните для расшифровки):");
                    Console.WriteLine($"p = {p}");
                    Console.WriteLine($"q = {q}");
                    Console.WriteLine($"n = {n}");
                    Console.WriteLine($"k = {k}");
                    Console.WriteLine($"\nПодпись (S1, S2):");
                    Console.WriteLine($"S1 = {S1}");
                    Console.WriteLine($"S2 = {S2}");

                    Console.WriteLine("\nДля расшифровки используйте эти параметры в режиме 2.");
                }
                else if (choice == "2")
                {
                    // Блок дешифрования: восстановление сообщений из подписи
                    Console.WriteLine("\nРежим расшифровки (S1,S2 -> x,y)");

                    // Ввод параметров, использованных при шифровании
                    Console.WriteLine("\nВведите параметры шифрования:");
                    BigInteger p = ReadBigInteger("p: ");
                    BigInteger q = ReadBigInteger("q: ");
                    BigInteger n = ReadBigInteger("n: ");
                    BigInteger k = ReadBigInteger("k: ");

                    // Проверка корректности параметров
                    if (n != p * q)
                    {
                        Console.WriteLine($"ОШИБКА: n должно равняться p*q ({p}*{q} = {p * q} ≠ {n})");
                        return;
                    }

                    // Проверка взаимной простоты k и n
                    if (BigInteger.GreatestCommonDivisor(k, n) != 1)
                    {
                        Console.WriteLine("ОШИБКА: k должно быть взаимно просто с n");
                        return;
                    }

                    // Ввод компонентов подписи
                    Console.WriteLine("\nВведите подпись:");
                    BigInteger S1 = ReadBigInteger("S1: ");
                    BigInteger S2 = ReadBigInteger("S2: ");

                    // Проверка диапазона подписи
                    if (S1 < 0 || S1 >= n || S2 < 0 || S2 >= n)
                    {
                        Console.WriteLine($"ОШИБКА: S1 и S2 должны быть в диапазоне 0-{n - 1}");
                        return;
                    }

                    // Восстановление сообщений
                    BigInteger invK = ModInverse(k, n);           // k^{-1} mod n
                    BigInteger invK2 = (invK * invK) % n;        // k^{-2} mod n
                    BigInteger x = (S1 * S1 - S2 * S2 * invK2) % n; // Восстановленное x
                    if (x < 0) x += n;  // Корректировка отрицательных значений
                    BigInteger y = (S1 - S2 * invK) % n;         // Восстановленное y
                    if (y < 0) y += n;  // Корректировка отрицательных значений

                    // Вывод результатов
                    Console.WriteLine("\nРасшифровка выполнена успешно!");
                    Console.WriteLine($"\nПубличное сообщение x: {x}");
                    Console.WriteLine($"Приватное сообщение y: {y}");
                }
                else
                {
                    Console.WriteLine("Неизвестный выбор. Программа завершена.");
                }
            }
            else
            {
                // Режим обучения с пошаговым выполнением операций

                // Шаг 1: Генерация простых чисел
                Console.WriteLine("ШАГ 1: Генерация больших простых чисел p и q");
                Console.WriteLine("--------------------------------------------");
                Console.WriteLine("Генерация 512-битного простого числа p...");
                BigInteger p = GeneratePrime(512);
                Console.WriteLine($"p = {FormatBigInteger(p)}");
                Console.WriteLine("\nГенерация 512-битного простого числа q...");
                BigInteger q = GeneratePrime(512);
                Console.WriteLine($"q = {FormatBigInteger(q)}");
                BigInteger n = p * q;
                Console.WriteLine($"\nВычислен модуль n = p * q");
                Console.WriteLine($"n = {FormatBigInteger(n)}");
                Console.WriteLine($"Длина n: {n.GetBitLength()} бит");
                WaitForEnter();

                // Шаг 2: Генерация секретного ключа
                Console.WriteLine("\nШАГ 2: Генерация секретного ключа k");
                Console.WriteLine("-----------------------------------");
                Console.WriteLine("Генерация k (взаимно простого с n)...");
                BigInteger k;
                using (var rng = RandomNumberGenerator.Create())
                {
                    do
                    {
                        k = GenerateRandomBigInteger(2, n - 1, rng);
                    } while (BigInteger.GreatestCommonDivisor(k, n) != 1);
                }
                Console.WriteLine($"k = {FormatBigInteger(k)}");
                Console.WriteLine($"НОД(k, n) = {BigInteger.GreatestCommonDivisor(k, n)} (должен быть 1)");
                WaitForEnter();

                // Шаг 3: Ввод и проверка сообщений
                Console.WriteLine("\nШАГ 3: Ввод сообщений");
                Console.WriteLine("----------------------");
                Console.WriteLine($"\nВведите сообщения (должны быть в диапазоне 2-{n - 1} и взаимно просты с n)");
                BigInteger x = ReadBigInteger("Введите публичное сообщение x (число): ");
                BigInteger y = ReadBigInteger("Введите приватное сообщение y (число): ");

                // Детальная проверка введенных значений
                Console.WriteLine($"\nПроверка условий:");
                Console.WriteLine($"1. 1 < x < n: {x > 1 && x < n}");
                Console.WriteLine($"2. 1 < y < n: {y > 1 && y < n}");
                Console.WriteLine($"3. НОД(x, n) = {BigInteger.GreatestCommonDivisor(x, n)}");
                Console.WriteLine($"4. НОД(y, n) = {BigInteger.GreatestCommonDivisor(y, n)}");

                if (x <= 1 || y <= 1 || x >= n || y >= n ||
                    BigInteger.GreatestCommonDivisor(x, n) != 1 ||
                    BigInteger.GreatestCommonDivisor(y, n) != 1)
                {
                    Console.WriteLine("\nОШИБКА: x и y должны удовлетворять условиям:");
                    Console.WriteLine("1. 1 < x < n");
                    Console.WriteLine("2. 1 < y < n");
                    Console.WriteLine("3. НОД(x, n) = 1");
                    Console.WriteLine("4. НОД(y, n) = 1");
                    return;
                }
                WaitForEnter();

                // Шаг 4: Вычисление подписи с объяснением формул
                Console.WriteLine("\nШАГ 4: Вычисление подписи (S1, S2)");
                Console.WriteLine("-----------------------------------");
                Console.WriteLine("Формулы:");
                Console.WriteLine("S1 = (1/2) * (x * y⁻¹ + y) mod n");
                Console.WriteLine("S2 = (1/2) * k * (x * y⁻¹ - y) mod n");

                BigInteger invY = ModInverse(y, n);
                Console.WriteLine($"\ny⁻¹ = {FormatBigInteger(invY)}");

                BigInteger term1 = (x * invY) % n;
                Console.WriteLine($"x * y⁻¹ = {FormatBigInteger(term1)}");

                BigInteger inv2 = ModInverse(2, n);
                Console.WriteLine($"1/2 mod n = {FormatBigInteger(inv2)}");

                // Вычисление компонентов подписи
                BigInteger S1 = (term1 + y) * inv2 % n;
                BigInteger S2 = k * (term1 - y) % n * inv2 % n;

                Console.WriteLine($"\nS1 = {FormatBigInteger(S1)}");
                Console.WriteLine($"S2 = {FormatBigInteger(S2)}");
                Console.WriteLine($"Подпись: (S1, S2) = ({FormatBigInteger(S1)}, {FormatBigInteger(S2)})");
                WaitForEnter();

                // Шаг 5: Обратное преобразование (верификация)
                Console.WriteLine("\nШАГ 5: Извлечение сообщений из подписи");
                Console.WriteLine("--------------------------------------");
                Console.WriteLine("Формулы:");
                Console.WriteLine("x' = S1² - S2² * k⁻² mod n");
                Console.WriteLine("y' = S1 - S2 * k⁻¹ mod n");

                BigInteger invK = ModInverse(k, n);
                Console.WriteLine($"\nk⁻¹ = {FormatBigInteger(invK)}");

                BigInteger invK2 = (invK * invK) % n;
                Console.WriteLine($"k⁻² = {FormatBigInteger(invK2)}");

                // Восстановление сообщений
                BigInteger xExtracted = (S1 * S1 - S2 * S2 * invK2) % n;
                if (xExtracted < 0) xExtracted += n;  // Нормализация

                BigInteger yExtracted = (S1 - S2 * invK) % n;
                if (yExtracted < 0) yExtracted += n;  // Нормализация

                Console.WriteLine($"\nИзвлеченное x' = {FormatBigInteger(xExtracted)}");
                Console.WriteLine($"Извлеченное y' = {FormatBigInteger(yExtracted)}");
                WaitForEnter();

                // Шаг 6: Проверка корректности
                Console.WriteLine("\nШАГ 6: Проверка корректности");
                Console.WriteLine("----------------------------");
                Console.WriteLine($"Оригинальное x: {x}");
                Console.WriteLine($"Извлеченное x': {xExtracted}");
                Console.WriteLine($"Совпадение: {x == xExtracted}");

                Console.WriteLine($"\nОригинальное y: {y}");
                Console.WriteLine($"Извлеченное y': {yExtracted}");
                Console.WriteLine($"Совпадение: {y == yExtracted}");

                Console.WriteLine("\nПроверка завершена!");
            }
        }

        // Вспомогательные методы -------------------------------------------------

        // Ожидание нажатия Enter (для пошагового режима)
        static void WaitForEnter()
        {
            Console.Write("\nНажмите Enter для продолжения...");
            Console.ReadLine();
            Console.WriteLine();
        }

        // Безопасное чтение BigInteger с консоли
        static BigInteger ReadBigInteger(string prompt)
        {
            Console.Write(prompt);
            while (true)
            {
                if (BigInteger.TryParse(Console.ReadLine(), out BigInteger result))
                    return result;
                Console.Write("Некорректный ввод. Пожалуйста, введите целое число: ");
            }
        }

        // Форматирование больших чисел для удобного отображения
        static string FormatBigInteger(BigInteger number)
        {
            string numStr = number.ToString();
            if (numStr.Length <= 10)
                return numStr;

            return $"{numStr.Substring(0, 5)}...{numStr.Substring(numStr.Length - 5)}" +
                   $" (всего {numStr.Length} цифр)";
        }

        // Генерация простого числа заданной битности
        static BigInteger GeneratePrime(int bits)
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[bits / 8 + 1];
            BigInteger prime;

            while (true)
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] = 0; // Гарантия положительного числа
                prime = new BigInteger(bytes);

                // Делаем нечетным
                if (prime.IsEven) prime++;

                // Проверка битности
                if (prime.GetBitLength() < bits) continue;

                // Тест Миллера-Рабина
                if (IsProbablePrime(prime, 15)) break;
            }

            return prime;
        }

        // Тест Миллера-Рабина на простоту
        static bool IsProbablePrime(BigInteger n, int certainty)
        {
            // Обработка тривиальных случаев
            if (n == 2 || n == 3) return true;
            if (n < 2 || n.IsEven) return false;

            // Подготовка к тесту: n-1 = 2^s * d
            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            byte[] bytes = new byte[n.ToByteArray().Length];
            using var rng = RandomNumberGenerator.Create();

            // Многократное тестирование
            for (int i = 0; i < certainty; i++)
            {
                BigInteger a;
                do
                {
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= n - 2);

                BigInteger x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1)
                    continue;

                bool primeFlag = false;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == 1) return false;
                    if (x == n - 1)
                    {
                        primeFlag = true;
                        break;
                    }
                }

                if (!primeFlag) return false;
            }

            return true;
        }

        // Генерация случайного BigInteger в диапазоне [min, max)
        static BigInteger GenerateRandomBigInteger(BigInteger min, BigInteger max, RandomNumberGenerator rng)
        {
            BigInteger result;
            byte[] bytes = max.ToByteArray();

            do
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] &= 0x7F; // Гарантия положительного числа
                result = new BigInteger(bytes);
            } while (result < min || result >= max);

            return result;
        }

        // Вычисление модульного обратного элемента (расширенный алгоритм Евклида)
        static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
    }
}