using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using StackExchange.Redis;

namespace decrypter_poc
{
    internal class Program
    {
        // ransomeware generated a "random" password between 30 and 50 characters
        private static readonly IEnumerable<int> pwLengths = Enumerable.Range(30, 20);
        // static salt was used for all key generation
        private static readonly byte[] saltBytes = {1, 2, 3, 4, 5, 6, 7, 8};


        public static byte[] AES_UM_Decrypt(byte[] bytesToBeDecrypted, byte[] computedKeys)
        {
            byte[] decryptedBytes = null;


            //AesManaged AES = new AesManaged
            //{
            //    KeySize = 256,
            //    BlockSize = 128,
            //    Mode = CipherMode.CBC

            //};

            // AesCryptoProvidor proved to be faster than the AesManaged functions
            using (var aes = new AesCryptoServiceProvider
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC
            })
            {
                //var keyBytes = AES.KeySize/8;
                //var ivBytes = AES.BlockSize/8;

                var keyBytes = new byte[32];
                var ivBytes = new byte[16];

                Buffer.BlockCopy(computedKeys, 0, keyBytes, 0, 32);
                Buffer.BlockCopy(computedKeys, 32, ivBytes, 0, 16);

                try
                {
                    using (var ms = new MemoryStream())
                    {
                        //var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        //AES.Key = key.GetBytes(keyBytes);
                        //AES.IV = key.GetBytes(ivBytes);
                        aes.Key = keyBytes;
                        aes.IV = ivBytes;

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
        
        /* same function from ransomeware, modified to take a static seed value.
         * This will produce predictable passwords given the same seed and length
         */
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

        public static byte[] genSha(string pass)
        {
            return SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(pass));
        }

        public static CalculatedSeed pullCache(int seed, ConnectionMultiplexer redis)
        {
            var db = redis.GetDatabase();
            var pwdHash = new HashEntry[1];
            var seedResult = new CalculatedSeed();
            try
            {
                pwdHash = db.HashGetAll(Convert.ToString(seed));
                seedResult = new CalculatedSeed(seed, pwdHash.ToDictionary());
            }
            catch (RedisConnectionException)
            {

            }
             
            return seedResult;
        }

        /* Takes input seed and generates passwords of lengths between 20-50 characters
         * These passwords are used to generate a key and an initialization vector, which are each stored as bytes
         * These values can be stored in Redis as byte arrays so that they only ever have to be calculated once
         */
        public static HashEntry[] createPwdHashes(int seed)
        {
            var hashList = new List<HashEntry>();

            foreach (int length in pwLengths)
            {
                // ransomeware actually used the SHA256 value of the password, not the actual generated password
                var pass = genSha(GetPass(length, seed));
                var passDeriveBytes = new Rfc2898DeriveBytes(pass, saltBytes, 1000);

                var passBytes = passDeriveBytes.GetBytes(256 / 8);
                var blockBytes = passDeriveBytes.GetBytes(128 / 8);

                var combinedArray = new byte[passBytes.Length + blockBytes.Length];

                Buffer.BlockCopy(passBytes, 0, combinedArray, 0, passBytes.Length);
                Buffer.BlockCopy(blockBytes, 0, combinedArray, passBytes.Length, blockBytes.Length);

                hashList.Add(new HashEntry(Convert.ToString(length), combinedArray));                
            }
           
            return hashList.ToArray();
        }

        // seed and directory of passwords for easy storage and indexing
        public class CalculatedSeed
        {
            public int seed { get; set; }

            public Dictionary<RedisValue, RedisValue> hashValues { get; set; }

            public CalculatedSeed(int seedValue, Dictionary<RedisValue, RedisValue> dict)
            {
                seed = seedValue;
                hashValues = dict;
            }

            public CalculatedSeed()
            {
                seed = 0;
                hashValues = new Dictionary<RedisValue, RedisValue>();
            }
        }


        public static bool tryDecrypt(EncryptedFile file, bool threading, List<CalculatedSeed> seedResults)
        {
            var stop = new Stopwatch();

            stop.Start();           

            foreach (var seedHash in seedResults)
            {
                if (threading)
                {
                    Parallel.ForEach(pwLengths, (pwlength, state) =>
                    {
                        var decrypted = AES_UM_Decrypt(file.cryptedFilebytes, seedHash.hashValues[Convert.ToString(pwlength)]);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file.file))
                            {

                                file.seed = seedHash.seed;
                                file.decryptedFilebyte = decrypted;
                                file.setPassword(genSha(GetPass(pwlength, seedHash.seed)));


                                file.decrypted = true;
                                state.Break();
                            }
                        }
                    });
                              
                    if (file.decrypted)
                    {
                        break;
                    }
                }
                else
                {
                    foreach (var pwlength in pwLengths)
                    {
                        var decrypted = AES_UM_Decrypt(file.cryptedFilebytes, seedHash.hashValues[Convert.ToString(pwlength)]);

                        if (decrypted != null)
                        {
                            if (Validate.checkValid(decrypted, file.file))
                            {

                                file.decrypted = true;
                                file.seed = seedHash.seed;
                                file.decryptedFilebyte = decrypted;
                                file.setPassword(genSha(GetPass(pwlength, seedHash.seed)));

                                return true;
                            }
                        }
                    }
                }
            }

            stop.Stop();            

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
            var delete = false;
            ConnectionMultiplexer redis = null;           


            var encryptedFiles = new List<EncryptedFile>();

            var result = Parser.Default.ParseArguments<Options>(args);

            // attempt to parse commandline options, write help if failed
            if (result.Tag == ParserResultType.Parsed)
            {
                var parsed = (Parsed<Options>) result;
                var options = parsed.Value;

                if (options.verbose)
                {
                    verbose = true;
                }

                // load either single file or directory
                if (options.cryptedFilePath != null)
                {
                    filePath = options.cryptedFilePath;
                    outdir = new FileInfo(filePath).Directory.ToString();
                    if (File.Exists(options.cryptedFilePath))
                    {
                        encryptedFiles.Add(new EncryptedFile(options.cryptedFilePath));
                    }
                    else
                    {
                        Console.WriteLine("Error: Input file not found");
                        return 2;
                    }
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

                if (options.delete)
                {
                    delete = options.delete;
                }

                if (options.redis != null)
                {
                    try
                    {
                        redis = ConnectionMultiplexer.Connect(options.redis);                       
                    }
                    catch (RedisConnectionException)
                    {
                        Console.WriteLine("Warning: Unable to connect to Redis server. Disabling caching");
                        redis = null;                        
                    }
                }

            }
            else
            {
                var failedParse = (NotParsed<Options>) result;                
                return 2;
            }
            
            // loop through file(s) and attempt decryption           
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

                // load encrypted file into memory
                cryptFile.loadBytes();

                if (verbose)
                {
                    Console.WriteLine("Attmepting to decrypt: {0}", cryptFile.file.Name);
                    Console.WriteLine("Starting at seed count {0}", startSeed);
                }

                var seedResults = new List<CalculatedSeed>();
                var decryptResult = false;
                int loopCount = 0;

                for (var seed = endSeed; seed > startSeed; seed--)
                {
                    if (redis != null)
                    {
                        var db = redis.GetDatabase();

                        CalculatedSeed cacheHit = null;

                        // attempt to pull from redis cache
                        try
                        {
                            cacheHit = pullCache(seed, redis);
                        }
                        catch (Exception)
                        {
                            cacheHit = new CalculatedSeed();
                        }

                        // check if hash was pulled, otherwise generate seed results in place, then attempt to add to redis
                        if (cacheHit.hashValues.Count != 0)
                        {
                            seedResults.Add(cacheHit);
                        }
                        else
                        {
                            var pwdHashes = createPwdHashes(seed);
                            var hashDict = pwdHashes.ToDictionary();

                            try
                            {
                                db.HashSet(Convert.ToString(seed), pwdHashes);
                            }
                            catch (Exception)
                            {
                                Console.WriteLine("Warning: Unable to write to Redis");
                            }
                            seedResults.Add(new CalculatedSeed(seed, hashDict));
                        }
                    }
                    // if redis not enabled, just generate seed values and store in memory
                    else
                    {
                        seedResults.Add(new CalculatedSeed(seed, createPwdHashes(seed).ToDictionary()));
                    }

                    // check every 10 loops so that large buffers don't suck up memory
                    if (loopCount % 10 == 0)
                    {
                        decryptResult = decryptResult = tryDecrypt(cryptFile, multi, seedResults);
                        if (decryptResult)
                        {
                            break;
                        }
                        else
                        {
                            if (verbose)
                            {
                                Console.Write("\rAttempt number: {0}", loopCount);
                            }
                            seedResults = new List<CalculatedSeed>();
                        }
                    }
                    loopCount++;
                }

                decryptResult = tryDecrypt(cryptFile, multi, seedResults);

                if (decryptResult && cryptFile.seed != 0)
                {
                    Console.WriteLine("\nSuccessfully decrypted file. Writing to disk.");
                    Console.WriteLine("Password: {0}", cryptFile.password);
                    Console.WriteLine("Seed value: {0}", cryptFile.seed);
                    Console.WriteLine("Seed value was off by {0} milliseconds!", calDiff(fileTicks, cryptFile.seed));

                    try
                    {
                        writeDecryptedFile(cryptFile.file.FullName, cryptFile.decryptedFilebyte);
                        if (delete)
                        {
                            File.Delete(cryptFile.file.FullName);
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("Error: Unable to write decrypted file to disk. Access was denied to path.");
                    }
                }
                else
                {
                    Console.WriteLine("\nFailed to decrypt file!");
                }
            }
            return 0;
        }
    }
}
 