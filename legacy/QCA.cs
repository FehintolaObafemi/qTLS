using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace QuantumCrypto
{
    class QuantumCrypto
    {
        static void Main(string[] args)
        {
            // Set up the quantum communication channel
            QuantumChannel quantum_channel = new QuantumChannel();

            // Generate random bits for Alice and Bob
            Random rand = new Random();
            int[] alice_bits = Enumerable.Repeat(0, 100).Select(i => rand.Next(2)).ToArray();
            int[] bob_bits = Enumerable.Repeat(0, 100).Select(i => rand.Next(2)).ToArray();

            // Generate random basis for Alice and Bob
            int[] alice_basis = Enumerable.Repeat(0, 100).Select(i => rand.Next(2)).ToArray();
            int[] bob_basis = Enumerable.Repeat(0, 100).Select(i => rand.Next(2)).ToArray();

            // Alice encodes her bits using her basis
            int[] alice_encoded = Enumerable.Repeat(-1, 100).ToArray();
            for (int i = 0; i < 100; i++)
            {
                if (alice_basis[i] == 0)
                {
                    alice_encoded[i] = quantum_channel.SendQubit(alice_bits[i], QuantumState.Zero);
                }
                else
                {
                    alice_encoded[i] = quantum_channel.SendQubit(alice_bits[i], QuantumState.One);
                }
            }

            // Bob measures the qubits using his basis
            int[] bob_measured = Enumerable.Repeat(-1, 100).ToArray();
            for (int i = 0; i < 100; i++)
            {
                if (bob_basis[i] == 0)
                {
                    bob_measured[i] = quantum_channel.MeasureQubit(alice_encoded[i], QuantumState.Zero);
                }
                else
                {
                    bob_measured[i] = quantum_channel.MeasureQubit(alice_encoded[i], QuantumState.One);
                }
            }

            // Alice and Bob reveal their bases
            string alice_basis_string = string.Join("", alice_basis.Select(i => i.ToString()).ToArray());
            string bob_basis_string = string.Join("", bob_basis.Select(i => i.ToString()).ToArray());
            Console.WriteLine("Alice's basis: " + alice_basis_string);
            Console.WriteLine("Bob's basis: " + bob_basis_string);

            // Alice and Bob determine which qubits were measured in the same basis
            List<int> alice_matched = new List<int>();
            List<int> bob_matched = new List<int>();
            for (int i = 0; i < 100; i++)
            {
                if (alice_basis[i] == bob_basis[i])
                {
                    alice_matched.Add(i);
                    bob_matched.Add(i);
                }
            }

            // Alice and Bob perform error correction on the matched qubits
            int[] alice_corrected = Enumerable.Repeat(-1, 100).ToArray();
            int[] bob_corrected = Enumerable.Repeat(-1, 100).ToArray();
            for (int i = 0; i < alice_matched.Count; i++)
            {
                int idx = alice_matched[i];
                if (alice_encoded[idx] == bob_measured[idx])
                {
                    alice_corrected[idx] = alice_encoded[idx];
                    bob_corrected[idx] = bob_measured[idx];
                }
            }

            // Alice and Bob determine which qubits were successfully error-corrected
            List<int> alice_corrected_indices = new List<int>();
            List<int> bob_corrected_indices = new List<int>();
            for (int i = 0; i < 100; i++)
            {
                if (alice_corrected[i] != -1)
                {
                    alice_corrected_indices.Add(i);
                }
                if (bob_corrected[i] != -1)
                {
                    bob_corrected_indices.Add(i);
                }
            }

            // Alice and Bob compare a subset of their corrected bits to detect eavesdropping
            List<int> alice_discard = new List<int>();
            List<int> bob_discard = new List<int>();
            for (int i = 0; i < alice_corrected_indices.Count; i++)
            {
                int idx = alice_corrected_indices[i];
                if (rand.Next(2) == 0)
                {
                    alice_discard.Add(idx);
                }
                else
                {
                    bob_discard.Add(idx);
                }
            }

            // Alice and Bob discard the qubits that were measured in the wrong basis or that were used for error correction
            List<int> alice_shared = new List<int>();
            List<int> bob_shared = new List<int>();
            for (int i = 0; i < alice_corrected_indices.Count; i++)
            {
                int idx = alice_corrected_indices[i];
                if (!alice_discard.Contains(idx) && !bob_discard.Contains(idx))
                {
                    alice_shared.Add(alice_corrected[idx]);
                    bob_shared.Add(bob_corrected[idx]);
                }
            }

            // Alice and Bob compare their shared bits to confirm agreement
            bool agreement = alice_shared.SequenceEqual(bob_shared);
            if (agreement)
            {
                Console.WriteLine("Alice and Bob agreed on the shared key: " + string.Join("", alice_shared.Select(i => i.ToString()).ToArray()));
            }
            else
            {
                Console.WriteLine("Alice and Bob did not agree on the shared key.");
            }

            Console.ReadKey();
        }
    }
}

