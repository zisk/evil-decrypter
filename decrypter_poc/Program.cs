﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace decrypter_poc
{
    class Program
    {
        static int correctTick;

        // PNG magic byte header
        static byte[] PNG_MAGIC_BYTES = new byte[8] { 137, 80, 78, 71, 13, 10, 26, 10 };

        static bool checkPNG (byte[] decryptedBytes)
        {
            byte[] headerArray = new byte[8];

            Array.Copy(decryptedBytes, headerArray, 8);

            if (headerArray.SequenceEqual(PNG_MAGIC_BYTES))
            {
                return true;
            }
            else
            {
                return false;
            }
        }



        static public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            RijndaelManaged AES = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            };


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

        public static byte[] tryDecrypt(string file, int startSeed, int buffer)
        {
            byte[] fileBytes = File.ReadAllBytes(file);

            // set begining buffer
            int startOffset = startSeed - buffer;

            // set end buffer
            int endSeed = startSeed + buffer;

            int attemptTotal = (endSeed - startOffset) * 20;
            int attemptNumber = 0;

            IEnumerable<int> pwLengths = Enumerable.Range(30, 20);

            var stop = new System.Diagnostics.Stopwatch();

            byte[] decryptedFile = new byte[0]; 
            stop.Start();

            int offsetAtDecrypted = 0;
            var IsDecrypted = false;

            for (int seed = startOffset; seed < endSeed; seed++)
            {
                //start password length at 30, loop until 50

                //for (int pwlength = 30; pwlength < 50; pwlength++)


                Parallel.ForEach(pwLengths, (pwlength, state) =>
                {
                    string pass = GetPass(pwlength, seed);
                    // orginal ransomware appears to use a hash of the password rather than the real password
                    byte[] passBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
                    byte[] decrypted = AES_Decrypt(fileBytes, passBytes, saltBytes);


                    //Debug.WriteLine("Will this allow me in the loops?");

                    if (decrypted != null)
                    {
                        if (checkPNG(decrypted))
                        {
                            correctTick = seed;
                            offsetAtDecrypted = seed;

                            decryptedFile = decrypted;

                            state.Break();
                            IsDecrypted = true;

                        }

                    }
                    //attemptNumber++;
                    //if ((attemptNumber / 1000) == 1)
                    //{
                    //    Console.Write("\rAttempt {0}/{1}", attemptNumber, attemptTotal);
                    //}

                });

                
                //Console.WriteLine("Exhausted Seed: {0} Length: {1}", seed, pwlength);
                //});

                if (IsDecrypted)
                    {
                        break;
                    }
                
            }
                stop.Stop();
                Console.WriteLine("{0} time Elastped, Decrypted seed value {1}", stop.Elapsed, offsetAtDecrypted);
                // Console.ReadLine();
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
            File.WriteAllBytes(cleanFile ,decryptedBytes);
        }

        public static int getTicks(DateTime bootDate, string decryptFile)
        {
            DateTime lastWrite = File.GetLastWriteTime(decryptFile);

            TimeSpan dateDiff = lastWrite - bootDate;

            var currentTick = Convert.ToInt32(dateDiff.TotalMilliseconds);

            return currentTick;
        }

        public static DateTime calcActualBoot(string cryptedfile, int foundSeed)
        {
            DateTime fileLastWrite = File.GetLastWriteTime(cryptedfile);
            TimeSpan seedConvert = TimeSpan.FromMilliseconds(foundSeed);
            DateTime actualBoot = fileLastWrite.Subtract(seedConvert);
            return actualBoot;
        }

        static void Main(string[] args)
        {
            byte[] decryptedArray;
            string filePath;
            DateTime startDate;
            int mBuffer;

            if (args.Length == 0)
            {
                Console.WriteLine("Enter full path of encrypted file:");
                filePath = Console.ReadLine();

                if (filePath == "")
                {
                    filePath = @"K:\Temp\Mike Young\googlelogo.png.evil";
                }

                Console.WriteLine("Enter boot date:");

                var strStartDate = Console.ReadLine();

                if (strStartDate == "")
                {
                    startDate = Convert.ToDateTime(@"6/22/2016 8:41:18 AM");
                } else
                {
                    startDate = Convert.ToDateTime(strStartDate);
                }

                Console.WriteLine("Set time buffer (miliseconds)");
                var strBuffer = Console.ReadLine();
               

                if (strBuffer == "")
                {
                    mBuffer = 1000;
                } else
                {
                    mBuffer = Convert.ToInt32(strBuffer);
                }
            }
            else
            {
                filePath = args[0];
                startDate = Convert.ToDateTime(args[1]);
                mBuffer = Convert.ToInt32(args[2]);
            }

            int startTicks = getTicks(startDate, filePath);

            Console.WriteLine("Attempting decryption...");

            decryptedArray = tryDecrypt(filePath, startTicks, mBuffer);

            if (decryptedArray != null)
            {
                Console.WriteLine("\nSuccesfully decrypted file. Writing to disk.");
                Console.WriteLine("Seed value: {0}", correctTick);
                DateTime calcDate = calcActualBoot(filePath, correctTick);
                Console.WriteLine("Machine Boot Time: {0}", calcDate);

                writeDecryptedFile(filePath, decryptedArray);
            }
            else 
            {
                Console.WriteLine("\nFailed to decrypt file!");
            }
        }
    }
}
