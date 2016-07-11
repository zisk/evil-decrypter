using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace decrypter_poc
{
    

    class Validate
    {
        // png header bytes
        static byte[] PNG_MAGIC_BYTES = new byte[8] { 137, 80, 78, 71, 13, 10, 26, 10 };

        // officex header bytes
        static byte[] officexHeader = new byte[5] { 80, 75, 3, 4, 20 };

        // old office files
        static byte[] officeHeader = new byte[] { 208, 207, 17, 224 };

        static byte[] pdfHeader = new byte[] {37, 80, 68, 70, 45 };


        public static bool checkValid(byte[] fileDecrypt, FileInfo orgFile)
        {
            string[] fileSplit = orgFile.Name.Split('.');
            string ext = fileSplit[fileSplit.Length - 2];

            switch (ext)
            {
                case "xlsx":
                case "docx":
                case "pptx":
                case "vdsx":
                    return confirmValid(fileDecrypt, officexHeader);
                case "xls":
                case "doc":
                case "ppt":
                case "msg":
                    return confirmValid(fileDecrypt, officeHeader);
                case "png":
                    return confirmValid(fileDecrypt, PNG_MAGIC_BYTES);
                case "pdf":
                    return confirmValid(fileDecrypt, pdfHeader);
                default:
                    return false;
            }
        }


        public static bool confirmValid(byte[] fileBytes, byte[] headerCheck)
        {
            byte[] headerArray = new byte[headerCheck.Length];

            Array.Copy(fileBytes, headerArray, headerCheck.Length);

            if (headerArray.SequenceEqual(headerCheck))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
