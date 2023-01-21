using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;

namespace server_client_key_exchange{
    public partial class Client : Window{
        //Constants
        private const string IP_ADDRESS = "127.0.0.1";
        private const int PORT = 1236;
        private const int MSG_SIZE = 1024;

        public Client() {
            InitializeComponent();

            /* It creates a new ECDiffieHellmanCng object which is used for the key exchange.
              The key exchange is based on the elliptic curve cryptography (ECC) algorithm.
              The key size is 256 bits.
             */

            var client = new ECDiffieHellmanCng();
            client.KeyDerivationFunction =
                ECDiffieHellmanKeyDerivationFunction.Hash;
            client.HashAlgorithm = CngAlgorithm.Sha256;
            var key = client.PublicKey.ToByteArray();
            OutputBox.Text += "Sending my key to the server.\n";


            /* Creating a new TCP client, connecting to the server, sending the public key, and waiting for the server to
            send his. */

            var tcpClient = new TcpClient();
            tcpClient.Connect(IP_ADDRESS, PORT);
            OutputBox.Text +=
                "CLIENT: Sending my public key: " + Convert.ToBase64String(key) + "\n" + "sending...\n";
            var ns = tcpClient.GetStream();
            Send(ns, key);
            OutputBox.Text +=
                "CLIENT: I sent my public key, waiting for the server to send his. \n";


            // Receiving the public key from the server. 

            var data = Receive(ns);
            OutputBox.Text += "CLIENT: I just got the servers public key.\n" + "The key is: " +
                              Convert.ToBase64String(data) + "\n";

            // We now have both public keys, we can now generate the shared IV.

            var IV = Encoding.UTF8.GetBytes(RandomString());
            Send(ns, IV);
            OutputBox.Text += "CLIENT: I'm sending my IV -- initialization vector : " +
                              Convert.ToBase64String(IV) + "\n";


            // Calculating the symmetrical key using the server's public key and the client's private key. 

            OutputBox.Text +=
                "CLIENT: I will now calculate symmetrical key using server's public key and my private key \n";

            var symmetricalKey = client.DeriveKeyMaterial(
                ECDiffieHellmanCngPublicKey.FromByteArray(data, CngKeyBlobFormat.EccPublicBlob));
            OutputBox.Text +=
                "CLIENT: Calculated the symmetrical key, encrypting it with AES encryption. \n";

            // Encrypting the message with AES encryption. 

            const string message = "Encrypt this message with AES";
            var encrypted = EncryptMessage(message, symmetricalKey, IV);

            // Sending the encrypted message to the server.
            // Also sending the file.
            OutputBox.Text += "CLIENT: Encrypted my message: \n" + Convert.ToBase64String(encrypted);
            Send(ns, encrypted);
            SendFile(ns,
                @"D:\Projects\College\C#\server-client-key-exchange\server-client-key-exchange\server-client-key-exchange\Files\t.txt",
                symmetricalKey, IV);

            OutputBox.Text += "CLIENT: I am done on my side! Goodbye!";
            tcpClient.Close();
        }

        // Receive method
        private static byte[] Receive(NetworkStream networkStream) {
            try {
                // Reading the data from the network stream and writing it into a memory stream. 
                var receive = new byte[MSG_SIZE];
                var dataStream = new MemoryStream();
                var bytesRead = networkStream.Read(receive, 0, MSG_SIZE);
                while (bytesRead > 0) {
                    dataStream.Write(receive, 0, bytesRead);
                    if (networkStream.DataAvailable)
                        bytesRead = networkStream.Read(receive, 0, receive.Length);
                    else break;
                }

                return dataStream.ToArray();
            }
            catch (Exception) {
                MessageBox.Show("Error receiving data!");
                return null;
            }
        }


        // Send method
        private static void Send(NetworkStream networkStream, byte[] message) {
            try {
                networkStream.Write(message, 0, message.Length);
            }
            catch (Exception) {
                MessageBox.Show("Error Sending Data");
            }
        }

        /// It creates a byte array of 16 bytes, fills it with random data, converts the random data to a hexadecimal
        /// string, and returns the string
        private string RandomString() {
            var strBuild = new StringBuilder();
            if (strBuild == null) throw new ArgumentNullException(nameof(strBuild));
            var random = new Random();

            for (var i = 0; i < 16; i++) {
                var randomDouble = random.NextDouble();
                // Generating a random number between 0 and 25. 
                // ASCII A-Z is 65-90.
                var shift = Convert.ToInt32(Math.Floor(25 * randomDouble));
                var letter = Convert.ToChar(shift + 65);
                strBuild.Append(letter);
            }

            return strBuild.ToString();
        }


        /// Create a new AES object, create an encryptor, create a memory stream, create a crypto stream, create a stream
        /// writer, write the message to the stream, convert the stream to a byte array, and return the byte array.
        private static byte[] EncryptMessage(string message, byte[] Key, byte[] IV) {
            byte[] returnEncrypted;
            using (var aes = new AesManaged()) {
                var encryptor = aes.CreateEncryptor(Key, IV);
                using (var memoryStream = new MemoryStream()) {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
                        // Create StreamWriter and write data to a stream    
                        using (var streamWriter = new StreamWriter(cryptoStream)) {
                            streamWriter.Write(message);
                        }

                        returnEncrypted = memoryStream.ToArray();
                    }
                }
            }

            return returnEncrypted;
        }

        private static byte[] EncryptFile(byte[] data, byte[] Key, byte[] IV) {
            using (var aes = new AesManaged()) {
                aes.Padding = PaddingMode.PKCS7;
                var encryptor = aes.CreateEncryptor(Key, IV);
                using (var memoryStream = new MemoryStream()) {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        private void UIElement_OnMouseLeftButtonDown(object sender, MouseButtonEventArgs e) {
            try {
                if (e.ChangedButton == MouseButton.Left)
                    DragMove();
            }
            catch (Exception) {
                //IGNORE
            }
        }


        private static void SendFile(NetworkStream networkStream, string filePath, byte[] key, byte[] IV) {
            // Read the image file into a byte array
            var fileBytes = File.ReadAllBytes(filePath);

            // Send the encrypted file bytes over the network stream in chunks
            var index = 0;
            while (index < fileBytes.Length) {
                // Determine the size of the next chunk
                var chunkSize = Math.Min(1024, fileBytes.Length - index);
                // Extract the next chunk from the file bytes
                var chunkBytes = new byte[chunkSize];
                Array.Copy(fileBytes, index, chunkBytes, 0, chunkSize);
                // Encrypt the chunk
                var encryptedChunkBytes = EncryptFile(chunkBytes, key, IV);
                // Send the encrypted chunk over the network stream
                networkStream.Write(encryptedChunkBytes, 0, encryptedChunkBytes.Length);
                // Move to the next chunk
                index += chunkSize;
            }
        }
    }
}