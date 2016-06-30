using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using Newtonsoft.Json;


namespace decrypter_poc
{
    internal class Program
    {
        private static int correctTick;

        private static readonly IEnumerable<int> pwLengths = Enumerable.Range(30, 20);

        private static readonly byte[] saltBytes = {1, 2, 3, 4, 5, 6, 7, 8};


        public static byte[] AES_UM_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;


            //AesManaged AES = new AesManaged
            //{
            //    KeySize = 256,
            //    BlockSize = 128,
            //    Mode = CipherMode.CBC

            //};

            using (var aes = new AesCryptoServiceProvider
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            })
            {
                var keyBytes = aes.KeySize/8;
                var ivBytes = aes.BlockSize/8;


                try
                {
                    using (var ms = new MemoryStream())
                    {
                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        aes.Key = key.GetBytes(keyBytes);
                        aes.IV = key.GetBytes(ivBytes);

                        using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.FlushFinalBlock();
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                }
                catch (Exception e)
                {
                }

                return decryptedBytes;
            }
        }


        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            var AES = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            };

            //AesManaged AES = new AesManaged
            //{
            //    KeySize = 256,
            //    BlockSize = 128,
            //    Mode = CipherMode.CBC

            //};

            var keyBytes = AES.KeySize/8;
            var ivBytes = AES.BlockSize/8;


            try
            {
                using (var ms = new MemoryStream())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(keyBytes);
                    AES.IV = key.GetBytes(ivBytes);

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            catch (Exception e)
            {
            }

            return decryptedBytes;
        }


        public static string GetPass(int x, int seed)
        {
            var str = "";
            var random = new Random(seed);
            while (str.Length < x)
            {
                var c = (char) random.Next(33, 125);
                if (char.IsLetterOrDigit(c))
                    str += c;
            }
            return str;
        }

        public static bool tryDecrypt(EncryptedFile file, int startSeed, int endseed, bool threading)
        {
            //byte[] fileBytes = File.ReadAllBytes(file);

            //int attemptTotal = (endSeed - startOffset) * 20;
            //int attemptNumber = 0;

            var stop = new Stopwatch();

            //byte[] decryptedFile = new byte[0];
            stop.Start();

            //int offsetAtDecrypted = 0;
            //var IsDecrypted = false;

            for (var seed = endseed; seed > startSeed; seed--)
            {
                if (threading)
                {
                    Parallel.ForEach(pwLengths, (pwlength, state) =>
                    {
                        var pass = GetPass(pwlength, seed);
                        // orginal ransomware appears to use a hash of the password rather than the real password
                        var passBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
                        var decrypted = AES_UM_Decrypt(file.cryptedFilebytes, passBytes, saltBytes);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file.file))
                            {
                                //correctTick = seed;
                                //offsetAtDecrypted = seed;

                                //decryptedFile = decrypted;

                                file.seed = seed;
                                file.decryptedFilebyte = decrypted;
                                file.setPassword(passBytes);

                                //IsDecrypted = true;

                                file.decrypted = true;
                                state.Break();
                            }
                        }
                    });

                    //Console.WriteLine("Exhausted Seed: {0} Length: {1}", seed, pwlength);               
                    if (file.decrypted)
                    {
                        break;
                    }
                }
                else
                {
                    foreach (var pwlength in pwLengths)
                    {
                        var pass = GetPass(pwlength, seed);
                        // orginal ransomware appears to use a hash of the password rather than the real password
                        var passBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
                        var decrypted = AES_UM_Decrypt(file.cryptedFilebytes, passBytes, saltBytes);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file.file))
                            {
                                //correctTick = seed;
                                //offsetAtDecrypted = seed;

                                file.decrypted = true;
                                file.seed = seed;
                                file.decryptedFilebyte = decrypted;
                                file.setPassword(passBytes);

                                //decryptedFile = decrypted;
                                //IsDecrypted = true;
                                return true;
                            }
                        }
                    }
                }
            }

            stop.Stop();
            // Console.WriteLine("{0} time Elastped, Decrypted seed value {1}", stop.Elapsed, offsetAtDecrypted);

            if (file.decryptedFilebyte != null)
            {
                return true;
            }
            return false;
        }

        public static void writeDecryptedFile(string cryptedFile, byte[] decryptedBytes)
        {
            // create directory
            var decryptedDir = Directory.CreateDirectory(Path.GetDirectoryName(cryptedFile) + @"\decrypted");
            var cleanFile = Path.Combine(decryptedDir.FullName, Path.GetFileName(cryptedFile.Replace(".evil", "")));
            File.WriteAllBytes(cleanFile, decryptedBytes);
        }

        public static int getTicks(DateTime bootDate, string decryptFile)
        {
            var lastWrite = File.GetLastWriteTime(decryptFile);
            var dateDiff = lastWrite - bootDate;
            var currentTick = Convert.ToInt32(dateDiff.TotalMilliseconds);

            // add 1000 milisecond to the start to account for lack of precision in last write
            currentTick += 1000;

            return currentTick;
        }

        public static int calDiff(int intialEndSeed, int foundSeed)
        {
            return intialEndSeed - 1000 - foundSeed;
        }


        private static int Main(string[] args)
        {
            //byte[] decryptedArray;
            var filePath = "";
            var startDate = DateTime.MinValue;
            var startSeed = 0;
            var endSeed = 0;
            var multi = false;
            int fileTicks;
            int buffer;
            int offset;
            string outdir;
            var verbose = false;
            //EncryptedFile cryptFile;

            var encryptedFiles = new List<EncryptedFile>();

            var result = Parser.Default.ParseArguments<Options>(args);


            if (result.Tag == ParserResultType.Parsed)
            {
                var parsed = (Parsed<Options>) result;
                var options = parsed.Value;

                if (options.verbose)
                {
                    verbose = true;
                }

                if (options.cryptedFilePath != null)
                {
                    filePath = options.cryptedFilePath;
                    outdir = new FileInfo(filePath).Directory.ToString();
                    encryptedFiles.Add(new EncryptedFile(options.cryptedFilePath));
                }
                else if (options.dir != null)
                {
                    if (Directory.Exists(options.dir))
                    {
                        outdir = options.dir;

                        if (verbose)
                        {
                            Console.WriteLine("Scanning directory {0} for encrypted files", options.dir);
                        }

                        foreach (var file in Directory.EnumerateFiles(options.dir, "*.evil*"))
                        {
                            encryptedFiles.Add(new EncryptedFile(file));
                        }

                        if (verbose)
                        {
                            Console.WriteLine("Found {0} encrypted files.", encryptedFiles.Count);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error: Invalid directory!");
                        return 2;
                    }
                }
                else
                {
                    Console.WriteLine("Error: Either a file or directory must be specified");
                    return 2;
                }

                try
                {
                    startDate = Convert.ToDateTime(options.bootDate);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Error: Unable to parse date");
                    return 1;
                }

                //cryptFile = new EncryptedFile(filePath);

                offset = options.offset;
                buffer = options.buffer;

                if (options.multi)
                {
                    multi = true;
                    if (verbose)
                    {
                        Console.WriteLine("Running in multithreaded mode");
                    }
                }
            }
            else
            {
                var failedParse = (NotParsed<Options>) result;
                //Console.WriteLine(options.GetUsage());
                return 2;
            }


            //decryptedArray = tryDecrypt(cryptFile, startSeed, endSeed, multi);

            foreach (var cryptFile in encryptedFiles)
            {
                fileTicks = getTicks(startDate, cryptFile.file.FullName);

                startSeed = fileTicks - offset - buffer;
               endSeed = fileTicks - offset;

                if (startSeed == 0 || endSeed == 0)
                {
                    Console.WriteLine("Ran out of numbers!");
                    break;
                }

                cryptFile.loadBytes();

                if (verbose)
                {
                    Console.WriteLine("Attmepting to decrypt: {0}", cryptFile.file.Name);
                    Console.WriteLine("Starting at seed count {0}", startSeed);
                }

                var decryptResult = tryDecrypt(cryptFile, startSeed, endSeed, multi);


                if (decryptResult && cryptFile.seed != 0)
                {
                    Console.WriteLine("\nSuccessfully decrypted file. Writing to disk.");
                    Console.WriteLine("Password: {0}", cryptFile.password);
                    Console.WriteLine("Seed value: {0}", cryptFile.seed);
                    Console.WriteLine("Seed value was off by {0} milliseconds!", calDiff(fileTicks, cryptFile.seed));

                    try
                    {
                        writeDecryptedFile(cryptFile.file.FullName, cryptFile.decryptedFilebyte);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("Error: Unable to write decrypted file to disk. Access was denied to path.");
                    }
                    //return 0;
                }
                else
                {
                    Console.WriteLine("\nFailed to decrypt file!");
                    //return 0;
                }

                if (verbose)
                {
                    Console.WriteLine("Writing results to JSON file");
                }

                try
                {
                    using (var jfile = File.CreateText(outdir + @"\files.json"))
                    {
                        JsonSerializer jserial = new JsonSerializer();
                        jserial.Serialize(jfile, encryptedFiles);
                    }
                }
                catch (IOException)
                {
                    Console.WriteLine("Unable to write to results file");
                }
            }
            return 0;
        }
    }
}