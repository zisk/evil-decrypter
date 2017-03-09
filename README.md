## Evil Decrypter

Brute force decrypted for NegozI Ransomware, which encrypts file to the .evil extension. 

Each file is encrypted with a unique key based on the uptime of the machine so a boot time much be provided. This is logged every day with the ID of 6013. Likewise, the write time of the file should be preserved so that the program can work backwords from there. You can also use a Redis sever for caching keys once they are calculated, which may save time the more files are run through.

Like the original malware, requires .NET 4.0 or greater.

```
  -f, --file       Full path to file to be decrypted

  --dir            Process all .evil files in directory

  -d, --date       Required. Time of machine boot.

  -b, --buffer     Required. Millisecond buffer to add on either side of time

  -o, --offset     Offset of beginning tick

  -v, --verbose    Verbose output

  --single         (Default: true) Run single threaded. (Default)

  --multi          (Default: false) Run multi threaded.

  --redis          Specify Redis server for caching.

  --del            Delete file if successfully decrypted

  --help           Display this help screen.

  --version        Display version information.
```