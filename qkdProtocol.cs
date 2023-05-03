using System.Collections;
using System.Security.Cryptography;

namespace qTLS
{
    /* This implementation generates random bits and qubits for Alice, transmits the qubits to Bob, measures the qubits, performs error correction 
    to obtain the sifted bits, and performs privacy amplification to generate a shared key. The implementation uses SHA256 for privacy amplification 
    and supports variable block sizes for error correction.
    */
    class QKDProtocol {

        public static Random rand = new Random();

        public static int[] GenerateBases(int numBits)
        {
            int[] bases = new int[numBits];
            for (int i = 0; i < numBits; i++)
            {
                bases[i] = rand.Next(2);
            }
            return bases;
        }

        public static Complex[] GenerateQubits(int numBits) 
        {
            Complex[] qubits = new Complex[numBits];
            for (int i = 0; i < numBits; i++) 
            {
                double theta = rand.NextDouble() * 2 * Math.PI;
                qubits[i] = new Complex(Math.Cos(theta), Math.Sin(theta));
            }
            return qubits;
        }

        public static Complex[] TransmitQubits(Complex[] qubits) 
        {
            Complex[] transmitted = new Complex[qubits.Length];
            for (int i = 0; i < qubits.Length; i++) 
            {
                transmitted[i] = qubits[i] * new Complex(rand.NextDouble() > 0.5 ? 1 : -1, 0);
            }
            return transmitted;
        }

        public static int[] MeasureBases(Complex[] qubits, int[] bases) 
        {
            int[] results = new int[qubits.Length];
            for (int i = 0; i < qubits.Length; i++) 
            {
                results[i] = bases[i] == 0 ? (qubits[i].Real > 0 ? 0 : 1) : (qubits[i].Imaginary > 0 ? 1 : 0);
            }
            return results;
        }

        public static int[] ErrorCorrection(int[] aliceBlock, int[] aliceBases, int[] bobBlock, int numBitsPerBlock) 
        {
            int[] siftedBits = new int[numBitsPerBlock];
            int numSiftedBits = 0;
            for (int i = 0; i < aliceBlock.Length; i += numBitsPerBlock) 
            {
                Dictionary<string, int> counts = new Dictionary<string, int>();
                for (int j = i; j < i + numBitsPerBlock; j++) 
                {
                    string key = aliceBases[j] + "," + bobBlock[j];
                    if (!counts.ContainsKey(key)) 
                    {
                        counts[key] = 0;
                    }
                    counts[key]++;
                }
                var maxCount = counts.Values.Max();
                var aliceBasis = -1;
                var bobBasis = -1;
                foreach (var entry in counts) 
                {
                    if (entry.Value == maxCount) 
                    {
                        string[] parts = entry.Key.Split(',');
                        aliceBasis = int.Parse(parts[0]);
                        bobBasis = int.Parse(parts[1]);
                        break;
                    }
                }
                if (aliceBasis != -1 && bobBasis != -1 && aliceBasis == bobBasis) 
                {
                    for (int j = i; j < i + numBitsPerBlock; j++) 
                    {
                        siftedBits[numSiftedBits++] = aliceBlock[j];
                    }
                }
            }
            return siftedBits.Take(numSiftedBits).ToArray();
        }

        public static byte[] PrivacyAmplification(int[] siftedBits, byte[] sharedSecret, int numBits)
        {
            byte[] hash = new byte[numBits / 8];
            using (var sha256 = SHA256.Create()) 
            {
                byte[] buffer = new byte[sharedSecret.Length + 4];
                for (int i = 0; i < numBits / 32; i++) 
                {
                    BitConverter.GetBytes(i).CopyTo(buffer, 0);
                    Array.Copy(sharedSecret, i * 4, buffer, 4, 4);
                    byte[] digest = sha256.ComputeHash(buffer);
                    Array.Copy(digest, 0, hash, i * 32 / 8, 32 / 8);
                }
            }
            BitArray bits = new BitArray(siftedBits);
            BitArray result = new BitArray(numBits);
            for (int i = 0; i < numBits; i++) 
            {
                result[i] = hash[i / 8] >> (7 - (i % 8)) & 1;
            }
            result.Xor(bits);
            byte[] output = new byte[numBits / 8];
            result.CopyTo(output, 0);
            return output;
        }
        /*static void Main(string[] args) 
        {
            int numBits = 1024;
            int numBitsPerBlock = 16;

            Console.WriteLine("QKD protocol with error correction and privacy amplification");
            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine("Generating random bits and qubits...");
            int[] aliceBits = Enumerable.Range(0, numBits).Select(i => rand.Next(2)).ToArray();
            int[] aliceBases = GenerateBases(numBits);
            Complex[] aliceQubits = GenerateQubits(numBits);

            Console.WriteLine("Transmitting qubits...");
            Complex[] bobQubits = TransmitQubits(aliceQubits);

            Console.WriteLine("Measuring qubits...");
            int[] bobBases = GenerateBases(numBits);
            int[] bobBits = MeasureBases(bobQubits, bobBases);

            Console.WriteLine("Performing error correction...");
            int[] siftedBits = ErrorCorrection(aliceBits, aliceBases, bobBits, numBitsPerBlock);

            Console.WriteLine("Performing privacy amplification...");
            byte[] sharedSecret = new byte[siftedBits.Length / 8];
            rand.NextBytes(sharedSecret);
            byte[] key = PrivacyAmplification(siftedBits, sharedSecret, numBits);

            Console.WriteLine("Key exchange complete. Shared key:");
            Console.WriteLine(BitConverter.ToString(key).Replace("-", ""));
        }*/

        public struct Complex 
        {
            public double Real { get; set; }
            public double Imaginary { get; set; }

            public Complex(double real, double imaginary) 
            {
                Real = real;
                Imaginary = imaginary;
            }

            public static Complex operator *(Complex a, Complex b) 
            {
                return new Complex(a.Real * b.Real - a.Imaginary * b.Imaginary, a.Real * b.Imaginary + a.Imaginary * b.Real);
            }
        }
    }
}
