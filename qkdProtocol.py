import numpy as np
from random import randint

# Define the basis for Alice and Bob
alice_basis = []
bob_basis = []

# Define the bits to be sent by Alice
alice_bits = []

# Define the photon states to be sent by Alice
alice_states = []

# Generate random bits to be sent by Alice
for i in range(100):
    alice_bits.append(randint(0, 1))

# Generate random basis for Alice and Bob
for i in range(100):
    alice_basis.append(randint(0, 1))
    bob_basis.append(randint(0, 1))

# Generate the photon states to be sent by Alice
for i in range(100):
    if alice_bits[i] == 0:
        if alice_basis[i] == 0:
            alice_states.append(np.array([1, 0]))
        else:
            alice_states.append(np.array([0, 1]))
    else:
        if alice_basis[i] == 0:
            alice_states.append(np.array([1/np.sqrt(2), 1/np.sqrt(2)]))
        else:
            alice_states.append(np.array([1/np.sqrt(2), -1/np.sqrt(2)]))

# Define the detection basis for Alice's decoy states
decoy_basis = []
for i in range(20):
    decoy_basis.append(randint(0, 1))

# Generate the decoy states to be sent by Alice
decoy_states = []
for i in range(20):
    if decoy_basis[i] == 0:
        decoy_states.append(np.array([1, 0]))
    else:
        decoy_states.append(np.array([0, 1]))

# Define the detection basis for Bob's measurement
bob_detection_basis = []
for i in range(120):
    bob_detection_basis.append(randint(0, 1))

# Define the error rate threshold
error_threshold = 0.05

# Define the privacy amplification hash function
hash_function = lambda x: x % 2

# Define the error correction parity matrix
parity_matrix = np.array([[1, 1, 0, 1], [1, 0, 1, 1]])

# Define the key size
key_size = 80

# Define the number of iterations for privacy amplification
iterations = 5

# Define the qubits received by Bob
bob_qubits = []

# Bob measures the qubits sent by Alice using his basis
for i in range(100):
    if bob_basis[i] == 0:
        bob_qubits.append(alice_states[i])
    else:
        measurement = np.random.choice([0, 1], p=[np.abs(alice_states[i][0])**2, np.abs(alice_states[i][1])**2])
        if measurement == 0:
            bob_qubits.append(np.array([1, 0]))
        else:
            bob_qubits.append(np.array([0, 1]))

# Bob measures the decoy states sent by Alice
decoy_results = []
for i in range(20):
    if decoy_basis[i] == 0:
        measurement = np.random.choice([0, 1], p=[1-np.exp(-0.1), np.exp(-0.1)])
    else:
        measurement = np.random.choice([0, 1], p=[np.exp(-0.1), 1-np.exp(-0.1)])
    if measurement == 0:
        decoy_results
