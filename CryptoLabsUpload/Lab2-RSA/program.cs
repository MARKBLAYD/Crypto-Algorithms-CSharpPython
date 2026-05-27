using System;
using System.IO;
using System.Numerics;
using System.Text;

class Program
{
    // Чтение файла
    static byte[] ReadFile(string filePath)
    {
        try
        {
            return File.ReadAllBytes(filePath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка чтения файла: {ex.Message}");
            return null;
        }
    }

    // Запись в файл
    static bool WriteFile(string filePath, byte[] data)
    {
        try
        {
            File.WriteAllBytes(filePath, data);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка записи в файл: {ex.Message}");
            return false;
        }
    }

    // Шифрование блока RSA (исправленная версия)
    static byte[] EncryptBlock(byte[] block, BigInteger e, BigInteger N)
    {
        // Преобразуем блок в BigInteger
        BigInteger message = new BigInteger(block, isUnsigned: true, isBigEndian: true);
        
        // Проверяем, что сообщение меньше N
        if (message >= N)
            throw new ArgumentException("Сообщение слишком большое для модуля N");

        // Шифруем
        BigInteger encrypted = BigInteger.ModPow(message, e, N);
        
        // Преобразуем результат в массив байт
        byte[] result = encrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
        
        return result;
    }

    // Дешифрование блока RSA (исправленная версия)
    static byte[] DecryptBlock(byte[] block, BigInteger d, BigInteger N)
    {
        // Преобразуем блок в BigInteger
        BigInteger encrypted = new BigInteger(block, isUnsigned: true, isBigEndian: true);
        
        // Проверяем, что зашифрованное сообщение меньше N
        if (encrypted >= N)
            throw new ArgumentException("Зашифрованное сообщение слишком большое для модуля N");

        // Расшифровываем
        BigInteger decrypted = BigInteger.ModPow(encrypted, d, N);
        
        // Преобразуем результат в массив байт
        byte[] result = decrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
        
        return result;
    }

    // Шифрование данных RSA (исправленная версия)
    static byte[] EncryptRSA(byte[] data, BigInteger e, BigInteger N)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            // Разбиваем данные на блоки подходящего размера
            int blockSize = GetBlockSize(N) - 1; // Оставляем место для padding
            int offset = 0;
            
            while (offset < data.Length)
            {
                int chunkSize = Math.Min(blockSize, data.Length - offset);
                byte[] block = new byte[chunkSize];
                Array.Copy(data, offset, block, 0, chunkSize);
                
                byte[] encryptedBlock = EncryptBlock(block, e, N);
                ms.Write(encryptedBlock, 0, encryptedBlock.Length);
                
                offset += chunkSize;
            }
            
            return ms.ToArray();
        }
    }

    // Дешифрование данных RSA (исправленная версия)
    static byte[] DecryptRSA(byte[] data, BigInteger d, BigInteger N)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            int blockSize = GetBlockSize(N);
            int offset = 0;
            
            while (offset < data.Length)
            {
                // Определяем размер текущего блока
                int chunkSize = Math.Min(blockSize, data.Length - offset);
                byte[] block = new byte[chunkSize];
                Array.Copy(data, offset, block, 0, chunkSize);
                
                byte[] decryptedBlock = DecryptBlock(block, d, N);
                ms.Write(decryptedBlock, 0, decryptedBlock.Length);
                
                offset += chunkSize;
            }
            
            return ms.ToArray();
        }
    }

    // Вычисление размера блока для данного модуля N
    static int GetBlockSize(BigInteger N)
    {
        return (N.ToByteArray(isUnsigned: true, isBigEndian: true).Length);
    }

    // Функция для чтения простого числа с проверкой
    static BigInteger ReadPrime(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            if (BigInteger.TryParse(Console.ReadLine(), out BigInteger number))
            {
                if (number < 2)
                {
                    Console.WriteLine("Число должно быть больше 1.");
                    continue;
                }

                if (IsProbablePrime(number, 10))
                {
                    return number;
                }
                else
                {
                    Console.WriteLine("Число не является простым. Попробуйте снова.");
                }
            }
            else
            {
                Console.WriteLine("Некорректный ввод. Введите целое число.");
            }
        }
    }

    // Функция для чтения экспоненты e с проверками
    static BigInteger ReadExponent(BigInteger phi)
    {
        while (true)
        {
            Console.Write($"Введите открытую экспоненту e (1 < e < {phi}, взаимно простое с φ(N)): ");
            if (BigInteger.TryParse(Console.ReadLine(), out BigInteger e))
            {
                if (e <= 1 || e >= phi)
                {
                    Console.WriteLine($"Экспонента должна быть в диапазоне: 1 < e < {phi}");
                    continue;
                }

                if (BigInteger.GreatestCommonDivisor(e, phi) != 1)
                {
                    Console.WriteLine($"Экспонента e должна быть взаимно простой с φ(N) = {phi}");
                    continue;
                }

                return e;
            }
            else
            {
                Console.WriteLine("Некорректный ввод. Введите целое число.");
            }
        }
    }

    // Генерация простого числа заданного размера
    static BigInteger GeneratePrime(int bitSize)
    {
        Random random = new Random();
        while (true)
        {
            byte[] bytes = new byte[bitSize / 8 + 1];
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; // Гарантируем положительное число
            BigInteger candidate = new BigInteger(bytes);
            
            // Убедимся, что число нечетное и достаточно большое
            if (candidate < 2 || candidate.IsEven)
                candidate += 1;

            // Проверяем на простоту
            if (IsProbablePrime(candidate, 10))
                return candidate;
        }
    }

    // Тест Миллера-Рабина на простоту
    static bool IsProbablePrime(BigInteger n, int k)
    {
        if (n == 2 || n == 3)
            return true;
        if (n < 2 || n.IsEven)
            return false;

        // Записываем n-1 как d*2^s
        BigInteger d = n - 1;
        int s = 0;
        while (d.IsEven)
        {
            d /= 2;
            s += 1;
        }

        Random random = new Random();
        byte[] bytes = new byte[n.ToByteArray().Length];
        
        for (int i = 0; i < k; i++)
        {
            BigInteger a;
            do
            {
                random.NextBytes(bytes);
                a = new BigInteger(bytes);
            }
            while (a < 2 || a >= n - 1);

            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
                continue;

            for (int j = 0; j < s - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == 1)
                    return false;
                if (x == n - 1)
                    break;
            }

            if (x != n - 1)
                return false;
        }

        return true;
    }

    // Главное меню
    static void Main()
    {
        while (true)
        {
            Console.Clear();
            Console.WriteLine("1. Сгенерировать ключи RSA");
            Console.WriteLine("2. Шифровать файл");
            Console.WriteLine("3. Дешифровать файл");
            Console.WriteLine("4. Выход");
            Console.Write("Выберите действие: ");

            string input = Console.ReadLine();
            if (!int.TryParse(input, out int choice) || choice < 1 || choice > 4)
            {
                Console.WriteLine("Неверный выбор!");
                Console.ReadLine();
                continue;
            }

            if (choice == 4)
                break;

            Console.Clear();

            try
            {
                if (choice == 1)
                {
                    Console.WriteLine("Генерация ключей RSA:");
                    Console.WriteLine("1. Ввести простые числа вручную");
                    Console.WriteLine("2. Сгенерировать простые числа автоматически");
                    Console.Write("Выберите способ: ");
                    
                    int genChoice;
                    while (!int.TryParse(Console.ReadLine(), out genChoice) || genChoice < 1 || genChoice > 2)
                    {
                        Console.Write("Неверный выбор. Введите 1 или 2: ");
                    }

                    BigInteger p, q;

                    if (genChoice == 1)
                    {
                        // Ручной ввод с проверками
                        p = ReadPrime("Введите простое число p: ");
                        q = ReadPrime("Введите простое число q: ");
                        
                        // Проверяем, что p и q разные
                        while (p == q)
                        {
                            Console.WriteLine("Числа p и q должны быть разными!");
                            q = ReadPrime("Введите простое число q (отличное от p): ");
                        }
                    }
                    else
                    {
                        // Автоматическая генерация
                        Console.Write("Введите размер простых чисел в битах (рекомендуется 32-512): ");
                        int bitSize;
                        while (!int.TryParse(Console.ReadLine(), out bitSize) || bitSize < 8 || bitSize > 1024)
                        {
                            Console.Write("Неверный размер. Введите число от 8 до 1024: ");
                        }

                        Console.WriteLine("Генерация простых чисел...");
                        p = GeneratePrime(bitSize);
                        q = GeneratePrime(bitSize);
                        
                        // Гарантируем, что p и q разные
                        while (p == q)
                        {
                            q = GeneratePrime(bitSize);
                        }

                        Console.WriteLine($"Сгенерировано p = {p}");
                        Console.WriteLine($"Сгенерировано q = {q}");
                    }

                    BigInteger N = p * q;
                    BigInteger phi = (p - 1) * (q - 1);

                    Console.WriteLine($"\nВычислено N = {N}");
                    Console.WriteLine($"Вычислено φ(N) = {phi}");

                    // Выбор экспоненты e
                    Console.WriteLine("\nВыберите открытую экспоненту e:");
                    Console.WriteLine("1. Использовать стандартное значение 65537");
                    Console.WriteLine("2. Ввести вручную");
                    Console.Write("Выберите вариант: ");
                    
                    int eChoice;
                    while (!int.TryParse(Console.ReadLine(), out eChoice) || eChoice < 1 || eChoice > 2)
                    {
                        Console.Write("Неверный выбор. Введите 1 или 2: ");
                    }

                    BigInteger e;
                    if (eChoice == 1)
                    {
                        e = 65537;
                        // Проверяем, подходит ли стандартное значение
                        if (e >= phi || BigInteger.GreatestCommonDivisor(e, phi) != 1)
                        {
                            Console.WriteLine("Стандартное значение e=65537 не подходит для этих p и q.");
                            Console.WriteLine("Попробуйте другие простые числа или введите e вручную.");
                            return;
                        }
                    }
                    else
                    {
                        e = ReadExponent(phi);
                    }

                    BigInteger d = ModInverse(e, phi);

                    Console.WriteLine("\nОткрытый ключ (e, N):");
                    Console.WriteLine($"e = {e}");
                    Console.WriteLine($"N = {N}");

                    Console.WriteLine("\nЗакрытый ключ (d, N):");
                    Console.WriteLine($"d = {d}");
                    Console.WriteLine($"N = {N}");

                    Console.WriteLine("\nСохраните эти ключи в безопасном месте!");
                }
                else if (choice == 2 || choice == 3)
                {
                    Console.Write("Введите путь к файлу: ");
                    string filePath = Console.ReadLine();

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("Файл не найден!");
                        Console.ReadLine();
                        continue;
                    }

                    byte[] fileData = ReadFile(filePath);
                    if (fileData == null)
                    {
                        Console.ReadLine();
                        continue;
                    }

                    Console.Write("Введите модуль N: ");
                    BigInteger N = BigInteger.Parse(Console.ReadLine());

                    byte[] result;
                    string outputFile;

                    if (choice == 2)
                    {
                        Console.Write("Введите открытую экспоненту e: ");
                        BigInteger e = BigInteger.Parse(Console.ReadLine());

                        result = EncryptRSA(fileData, e, N);
                        outputFile = filePath.Substring(0, filePath.Length - 4) + "_enc.txt";
                        Console.WriteLine("Шифрование выполнено.");
                    }
                    else
                    {
                        Console.Write("Введите закрытую экспоненту d: ");
                        BigInteger d = BigInteger.Parse(Console.ReadLine());

                        result = DecryptRSA(fileData, d, N);
                        outputFile = filePath.Substring(0, filePath.Length - 4) + "_dec.txt";
                        Console.WriteLine("Дешифрование выполнено.");
                    }

                    if (WriteFile(outputFile, result))
                    {
                        Console.WriteLine($"Результат сохранен в файл: {outputFile}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }

            Console.ReadLine();
        }
    }

    // Вычисление обратного элемента по модулю (расширенный алгоритм Евклида)
    static BigInteger ModInverse(BigInteger a, BigInteger m)
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

        if (x < 0)
            x += m0;

        return x;
    }
}