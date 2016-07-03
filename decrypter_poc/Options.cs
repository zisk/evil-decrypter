using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;

namespace decrypter_poc
{
    class Options
    {
        [Option('f', "file", HelpText = "Full path to file to be decrypted")]
        public string cryptedFilePath { get; set; }

        [Option("dir", HelpText ="Process all .evil files in directory")]
        public string dir { get; set; }

        [Option('d', "date", Required = true, 
            HelpText = "Time of machine boot.")]
        public string bootDate { get; set; }

        [Option('b', "buffer", Required = true, SetName = "buffer",
            HelpText = "Millisecond buffer to add on either side of time")]
        public int buffer { get; set; }

        [Option('o', "offset", 
            HelpText = "Offset of beginning tick")]
        public int offset { get; set; }

        [Option('v', "verbose", HelpText = "Verbose output")]
        public bool verbose { get; set; }

        [Option("single", HelpText = "Run single threaded. (Default)", Default = true)]
        public bool single { get; set; }

        [Option("multi", HelpText = "Run multi threaded.", Default = false)]
        public bool multi { get; set; }

        [Option("redis", HelpText = "Specify Redis server for caching.")]
        public string redis { get; set; }

        //[HelpOption]
        //public string GetUsage()
        //{
        //    var help = HelpText.AutoBuild(this);
        //    return help;
            
        //}
    }
}
