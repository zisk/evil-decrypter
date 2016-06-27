using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using CommandLine;
using CommandLine.Text;

namespace decrypter_poc
{
    class Program
    {
        static int correctTick;

        static IEnumerable<int> pwLengths = Enumerable.Range(30, 20);


        static public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            RijndaelManaged AES = new RijndaelManaged
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

            int keyBytes = AES.KeySize / 8;
            int ivBytes = AES.BlockSize / 8;


            try
            {
                using (MemoryStream ms = new MemoryStream())
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
            string str = "";
            Random random = new Random(seed);
            while (str.Length < x)
            {
                char c = (char)random.Next(33, 125);
                if (char.IsLetterOrDigit(c))
                    str += c;
            }
            return str;
        }

        static byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        public static byte[] tryDecrypt(string file, int startSeed, int endseed, bool threading)
        {
            byte[] fileBytes = File.ReadAllBytes(file);

            //int attemptTotal = (endSeed - startOffset) * 20;
            //int attemptNumber = 0;

            var stop = new System.Diagnostics.Stopwatch();

            byte[] decryptedFile = new byte[0]; 
            stop.Start();

            int offsetAtDecrypted = 0;
            var IsDecrypted = false;

            for (int seed = startSeed; seed < endseed; seed++)
            {
                if (threading)
                {
                    Parallel.ForEach(pwLengths, (pwlength, state) =>
                    {
                        string pass = GetPass(pwlength, seed);
                        // orginal ransomware appears to use a hash of the password rather than the real password
                        byte[] passBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
                        byte[] decrypted = AES_Decrypt(fileBytes, passBytes, saltBytes);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file))
                            {
                                correctTick = seed;
                                offsetAtDecrypted = seed;

                                decryptedFile = decrypted;

                                IsDecrypted = true;
                                state.Break();

                            }
                        }
                    });

                    //Console.WriteLine("Exhausted Seed: {0} Length: {1}", seed, pwlength);               
                    if (IsDecrypted)
                    {
                        break;
                    }

                }
                else
                {
                    foreach (int pwlength in pwLengths)
                    {
                        string pass = GetPass(pwlength, seed);
                        // orginal ransomware appears to use a hash of the password rather than the real password
                        byte[] passBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
                        byte[] decrypted = AES_Decrypt(fileBytes, passBytes, saltBytes);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file))
                            {
                                correctTick = seed;
                                offsetAtDecrypted = seed;

                                decryptedFile = decrypted;
                                IsDecrypted = true;
                                return decrypted;
                            }
                        }
                    }
                }
            }

            stop.Stop();
            Console.WriteLine("{0} time Elastped, Decrypted seed value {1}", stop.Elapsed, offsetAtDecrypted);

            if (decryptedFile != null)
            {
                return decryptedFile;
            } else
            {
                return null;
            }
        }

        public static void writeDecryptedFile(string cryptedFile, byte[] decryptedBytes)
        {
            // create directory
            DirectoryInfo decryptedDir = Directory.CreateDirectory(Path.GetDirectoryName(cryptedFile) + @"\decrypted");
            string cleanFile = Path.Combine(decryptedDir.FullName, Path.GetFileName(cryptedFile.Replace(".evil", "")));
            try
            {
                File.WriteAllBytes(cleanFile, decryptedBytes);
            }
            catch (System.UnauthorizedAccessException)
            {
                Console.WriteLine("Unable to write decrypted file to disk. Access was denied to path.");
            }
        }

        public static int getTicks(DateTime bootDate, string decryptFile)
        {
            DateTime lastWrite = File.GetLastWriteTime(decryptFile);
            TimeSpan dateDiff = lastWrite - bootDate;
            var currentTick = Convert.ToInt32(dateDiff.TotalMilliseconds);

            // add 1000 milisecond to the start to account for lack of precision in last write
            currentTick += 1000;                       

            return currentTick;
        }

        public static DateTime calcActualBoot(string cryptedfile, int foundSeed)
        {
            DateTime fileLastWrite = File.GetLastWriteTime(cryptedfile);
            TimeSpan seedConvert = TimeSpan.FromMilliseconds(foundSeed);
            DateTime actualBoot = fileLastWrite.Subtract(seedConvert);
            return actualBoot;
        }

        static int Main(string[] args)
        {
            byte[] decryptedArray;
            string filePath = "";
            DateTime startDate = DateTime.MinValue;
            int startSeed = 0;
            int endSeed = 0;
            bool multi = false;
            int fileTicks;

            var result = Parser.Default.ParseArguments<Options>(args);          


            if (result.Tag == ParserResultType.Parsed)
            {
                var parsed = (Parsed<Options>)result;
                var options = parsed.Value;

                filePath = options.cryptedFilePath;
                

                try
                {
                    startDate = Convert.ToDateTime(options.bootDate);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Error: Unable to parse date");
                   return 1;
                }

                fileTicks = getTicks(startDate, filePath);

                startSeed = fileTicks - options.buffer - options.offset;
                endSeed = fileTicks + options.offset - options.offset;

                if (options.multi)
                {
                    multi = true;
                }

            }   
            else
            {
                var failedParse = (NotParsed<Options>)result;                
                //Console.WriteLine(options.GetUsage());
                return 2;

            }        


            decryptedArray = tryDecrypt(filePath, startSeed, endSeed, multi);

            if (decryptedArray != null && correctTick != 0)
            {
                Console.WriteLine("\nSuccessfully decrypted file. Writing to disk.");
                Console.WriteLine("Seed value: {0}", correctTick);


                writeDecryptedFile(filePath, decryptedArray);
                return 0;
            }
            else 
            {
                Console.WriteLine("\nFailed to decrypt file!");
                return 0;
            }
        }
    }
}
