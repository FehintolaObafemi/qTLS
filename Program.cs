using System;
using System.Numerics;
namespace qTLS // Note: actual namespace depends on the project name.
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            // Quantum Key Distribution (QKD) implementation
            int numBits = 1024;
            int numBitsPerBlock = 16;

            Console.WriteLine("QKD protocol with error correction and privacy amplification");
            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine("Generating random bits and qubits...");
            int[] aliceBits = Enumerable.Range(0, numBits).Select(i => QKDProtocol.rand.Next(2)).ToArray();
            int[] aliceBases = QKDProtocol.GenerateBases(numBits);
            QKDProtocol.Complex[] aliceQubits = QKDProtocol.GenerateQubits(numBits);

            Console.WriteLine("Transmitting qubits...");
            QKDProtocol.Complex[] bobQubits = QKDProtocol.TransmitQubits(aliceQubits);

            Console.WriteLine("Measuring qubits...");
            int[] bobBases = QKDProtocol.GenerateBases(numBits);
            int[] bobBits = QKDProtocol.MeasureBases(bobQubits, bobBases);

            Console.WriteLine("Performing error correction...");
            int[] siftedBits = QKDProtocol.ErrorCorrection(aliceBits, aliceBases, bobBits, numBitsPerBlock);

            Console.WriteLine("Performing privacy amplification...");
            byte[] sharedSecret = new byte[siftedBits.Length / 8];
            QKDProtocol.rand.NextBytes(sharedSecret);
            byte[] key = QKDProtocol.PrivacyAmplification(siftedBits, sharedSecret, numBits);

            Console.WriteLine("Key exchange complete. Shared key:");
            Console.WriteLine(BitConverter.ToString(key).Replace("-", ""));
        }
    }
}