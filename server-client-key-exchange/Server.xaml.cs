using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Controls;

namespace server_client_key_exchange{
    public partial class Server : Window{
        // Constants
        private const string IP_ADDRESS = "127.0.0.1";
        private const int PORT = 1236;
        private const int MSG_SIZE = 1024;

        public Server() {
            InitializeComponent();
            /* It creates a new ECDiffieHellmanCng object which is used for the key exchange.
             The key exchange is based on the elliptic curve cryptography (ECC) algorithm.
             The key size is 256 bits.
            */
            var server = new ECDiffieHellmanCng();
            server.KeyDerivationFunction =
                ECDiffieHellmanKeyDerivationFunction.Hash;
            server.HashAlgorithm = CngAlgorithm.Sha256;


            // Creates a public key and also a private key in the background.

            var key = server.PublicKey.ToByteArray();
            OutputBox.Text += "SERVER: My public key: " + Convert.ToBase64String(key) + "\n";

            // Creating a new TCP listener, starting it, and accepting a client. 

            var tcpListener = new TcpListener(IPAddress.Parse(IP_ADDRESS), PORT);
            tcpListener.Start();
            OutputBox.Text += "SERVER: The client is connecting: " + Convert.ToBase64String(key) + "\n";
            var client = tcpListener.AcceptTcpClient();
            var ns = client.GetStream();

            // Receiving data from the client. 

            OutputBox.Text += "SERVER: I'm getting something from the client, \n";
            var data = Receive(ns);
            OutputBox.Text += "SERVER: I got the message:" + Convert.ToBase64String(data) + "\n";

            // Sending the public key to the client. 

            OutputBox.Text += "SERVER: The client sent me his public key, I'll send him mine:" +
                              Convert.ToBase64String(key) + "\n";
            Send(ns, key);

            // Waiting for the IV from the client. 

            OutputBox.Text +=
                "SERVER: I'll wait for the clients Initialization vector (IV) -> so I can decrypt the message. \n";
            OutputBox.Text += "SERVER: Getting the IV...\n";
            var IV = Receive(ns);

            // Calculating the symmetrical key from the private key and the client's public key. 
            OutputBox.Text +=
                "SERVER: I'll calculate the symmetrical key from my private key and client's public key. \n";

            var symmetricalKey = server.DeriveKeyMaterial(
                ECDiffieHellmanCngPublicKey.FromByteArray(data, CngKeyBlobFormat.EccPublicBlob));

            // Waiting for the client to send the encrypted message. 

            OutputBox.Text += "SERVER: Everything is ready, I'll wait for the client! \n";
            data = Receive(ns);
            ReceiveFile(ns,
                @"D:\Projects\College\C#\server-client-key-exchange\server-client-key-exchange\server-client-key-exchange\Received\trec.txt",
                symmetricalKey, IV);
            // Decrypting the message. 
            OutputBox.Text += "SERVER: I got the encrypted message:" + Convert.ToBase64String(data) + "\n" +
                              "SERVER: Decrypting...\n";
            var decrypted = Decrypt(data, symmetricalKey, IV);

            // Printing the decrypted message to the output box and then stopping the TCP listener. 
            OutputBox.Text += "SERVER: The decrypted message is: " + decrypted + "\n";
            tcpListener.Stop();
        }

        // Receive method
        private static byte[] Receive(NetworkStream networkStream) {
            try {
                // Reading the data from the network stream and writing it into a memory stream. */
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


        private static void ReceiveFile(NetworkStream networkStream, string filePath, byte[] key, byte[] IV) {
            // Create a list to store the chunks of the file
            var fileChunks = new List<byte>();
            // Receive the encrypted file chunks
            var buffer = new byte[1024];
            int bytesReceived;
            while ((bytesReceived = networkStream.Read(buffer, 0, buffer.Length)) > 0) {
                // Decrypt the chunk
                var decryptedChunkString = DecryptFile(buffer.Take(bytesReceived).ToArray(), key, IV);
                var bytes = Convert.FromBase64String(decryptedChunkString);
                fileChunks.AddRange(bytes);
            }
            // Save the decrypted file bytes to the specified file path
            File.WriteAllBytes(filePath, fileChunks.ToArray());
        }

        // Send method
        private static void Send(NetworkStream ns, byte[] message) {
            try {
                var send = message;
                ns.Write(send, 0, send.Length);
            }
            catch (Exception ex) {
                MessageBox.Show("Napaka pri pošiljanju!");
            }
        }

        /// Create a new AES object, create a decryptor, create a memory stream, create a crypto stream, create a stream
        /// read the message from the stream and write it into an empty string, and return the string.
        private static string Decrypt(byte[] data, byte[] Key, byte[] IV) {
            string msgPlaceholder = null;
            using (var aes = new AesManaged()) {
                var decryptor = aes.CreateDecryptor(Key, IV);
                using (var memoryStream = new MemoryStream(data)) {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)) {
                        using (var streamReader = new StreamReader(cryptoStream)) {
                            msgPlaceholder = streamReader.ReadToEnd();
                        }
                    }
                }
            }

            return msgPlaceholder;
        }

        private static string DecryptFile(byte[] data, byte[] Key, byte[] IV) {
            string msgPlaceholder = null;
            using (var aes = new AesManaged()) {
                aes.Padding = PaddingMode.PKCS7;
                var decryptor = aes.CreateDecryptor(Key, IV);
                using (var memoryStream = new MemoryStream(data)) {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)) {
                        using (var streamReader = new StreamReader(cryptoStream)) {
                            msgPlaceholder = streamReader.ReadToEndAsync().Result;
                        }
                    }
                }
            }

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(msgPlaceholder));
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
    }
}