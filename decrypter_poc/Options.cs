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
        [Option('f', "file", Required = true, HelpText = "Full path to file to be decrypted")]
        public string cryptedFilePath { get; set; }

        [Option('d', "date", SetName = "buffer", HelpText = "Time of machine boot.")]
        public string bootDate { get; set; }

        [Option('b', "buffer", SetName = "buffer",
            HelpText = "Millisecond buffer to add on either side of time")]
        public int buffer { get; set; }

        [Option('r', "range", SetName = "chunk", HelpText = "Offset of for begining tick")]
        public int range { get; set; }

        [Option('s', "starttick", SetName = "chunk", HelpText = "Milisecond count to start on")]
        public int start { get; set; }

        [Option("single", HelpText = "Run single threaded. (Default)", Default = true)]
        public bool single { get; set; }

        [Option("multi", HelpText = "Run multi threaded.", Default = false)]
        public bool multi { get; set; }

        //[HelpOption]
        //public string GetUsage()
        //{
        //    var help = HelpText.AutoBuild(this);
        //    return help;
            
        //}
    }
}
