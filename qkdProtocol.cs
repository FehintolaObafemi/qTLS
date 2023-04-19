using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace QKDProtocol
{
    class QKDProtocol
    {
        static void Main(string[] args)
        {
            // Generate random bits for Alice and Bob
            Random rand = new Random();
            int[] alice_bits = Enumerable.Repeat(0, 10).Select(i => rand.Next(2)).ToArray();
            int[] bob_bits = Enumerable.Repeat(0, 10).Select(i => rand.Next(2)).ToArray();

            // Generate random basis for Alice and Bob
            int[] alice_basis = Enumerable.Repeat(0, 10).Select(i => rand.Next(2)).ToArray();
            int[] bob_basis = Enumerable.Repeat(0, 10).Select(i => rand.Next(2)).ToArray();

            // Alice encodes her bits using her basis
            int[] alice_encoded = Enumerable.Repeat(-1, 10).ToArray();
            for (int i = 0; i < 10; i++)
            {
                if (alice_basis[i] == 0)
                {
                    alice_encoded[i] = alice_bits[i];
                }
                else
                {
                    alice_encoded[i] = (alice_bits[i] + 1) % 2;
                }
            }

            // Bob measures the qubits using his basis
            int[] bob_measured = Enumerable.Repeat(-1, 10).ToArray();
            for (int i = 0; i < 10; i++)
            {
                if (bob_basis[i] == 0)
                {
                    bob_measured[i] = alice_encoded[i];
                }
                else
                {
                    bob_measured[i] = (alice_encoded[i] + 1) % 2;
                }
            }

            // Alice and Bob reveal their bases
            string alice_basis_string = string.Join("", alice_basis.Select(i => i.ToString()).ToArray());
            string bob_basis_string = string.Join("", bob_basis.Select(i => i.ToString()).ToArray());
            Console.WriteLine("Alice's basis: " + alice_basis_string);
            Console.WriteLine("Bob's basis: " + bob_basis_string);

            // Alice and Bob discard the qubits measured in the wrong basis
            List<int> alice_discard = new List<int>();
            List<int> bob_discard = new List<int>();
            for (int i = 0; i < 10; i++)
            {
                if (alice_basis[i] != bob_basis[i])
                {
                    alice_discard.Add(i);
                    bob_discard.Add(i);
                }
            }

            // Alice and Bob compare a subset of their remaining bits to detect eavesdropping
            List<int> compare_indices = new List<int>() { 0, 3, 6, 9 };
            List<int> alice_compare = new List<int>();
            List<int> bob_compare = new List<int>();
            for (int i = 0; i < compare_indices.Count; i++)
            {
                int idx = compare_indices[i];
                alice_compare.Add(alice_encoded[idx]);
                bob_compare.Add(bob_measured[idx]);
            }

            bool eavesdropping_detected = false;
            for (int i = 0; i < compare_indices.Count; i++)
            {
                if (alice_compare[i] != bob_compare[i])
                {
                    eavesdropping_detected = true;
                    break;
                }
            }

            if (eavesdropping_detected)
            {
                Console.WriteLine("Eavesdropping detected!");
            }
            else
            {
                Console.WriteLine("No eavesdropping detected.");

                // Alice and Bob share the remaining qubits to generate the shared key
                List<int> alice_shared = new List<int>();
                List<int> bob_shared = new List<int>();
                for (int i = 0; i < 10; i++)
                {
                    if (!alice_discard.Contains(i) && !bob_discard.Contains(i))
                    {
                        alice_shared.Add(alice_encoded[i]);
                        bob_shared.Add(bob_measured[i]);
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
            }
        }
    }
}


