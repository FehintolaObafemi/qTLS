from qiskit import QuantumCircuit, Aer, execute
from qiskit.quantum_info import random_statevector
import numpy as np

# Generate random bit string to be encrypted
plaintext = '11001100'

# Initialize quantum circuit
num_qubits = len(plaintext)
qc = QuantumCircuit(num_qubits, num_qubits)

# Generate random key for the one-time pad
key = ''
for i in range(num_qubits):
    key += str(np.random.randint(2))

# Encode plaintext and key onto qubits
for i in range(num_qubits):
    if plaintext[i] == '1':
        qc.x(i)
    if key[i] == '1':
        qc.h(i)

# Send qubits through quantum channel
qubit_state = random_statevector(2**num_qubits)
qc.initialize(qubit_state.data, range(num_qubits))

# Measure qubits to generate ciphertext
qc.measure(range(num_qubits), range(num_qubits))

# Simulate the circuit and get measurement results
simulator = Aer.get_backend('qasm_simulator')
job = execute(qc, simulator, shots=1)
result = job.result()
ciphertext = list(result.get_counts().keys())[0][::-1]

# Decrypt ciphertext using the key
plaintext_decrypt = ''
for i in range(num_qubits):
    if key[i] == '1':
        plaintext_decrypt += str(int(ciphertext[i]) ^ 1)
    else:
        plaintext_decrypt += ciphertext[i]

# Verify that the decryption is correct
if plaintext == plaintext_decrypt:
    print("Encryption and decryption successful.")
else:
    print("Encryption and decryption failed.")
