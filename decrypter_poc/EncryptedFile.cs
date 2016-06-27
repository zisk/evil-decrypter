using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace decrypter_poc
{
    class EncryptedFile
    {

        public bool decrypted { get; set; }

        public FileInfo file;

        public byte[] cryptedFilebytes { get; }

        public bool ShouldSerializecryptedFilebytes()
        {
            return false;
        }

        public byte[] decryptedFilebyte { get; set; }

        public bool ShouldSerializedecryptedFilebyte()
        {
            return false;
        }

        public string password { get; set; }

        public int seed { get; set; }

        public string cryptedhash { get; set; }

        private string shaToString (byte [] shaBytes)
        {
            byte[] fileHash = SHA256.Create().ComputeHash(shaBytes);
            StringBuilder hashString = new StringBuilder();
            for (int i = 0; i < fileHash.Length; i++)
            {
                hashString.Append(fileHash[i].ToString("x2"));
            }

            return hashString.ToString();
        }

        public void setPassword (byte[] passBytes)
        {
            password = shaToString(passBytes);
        }
        
        public EncryptedFile(string filePath)
        {
            file = new FileInfo(filePath);

            cryptedhash = shaToString(File.ReadAllBytes(file.FullName));
            cryptedFilebytes = File.ReadAllBytes(file.FullName);
        }
    }
}
