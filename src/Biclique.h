#ifndef BICLIQUE_H
#define BICLIQUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Definitions for Biclique parameters
#define d 8.0 // Biclique dimension (defines size of differential transitions)
#define SSize 16 // Size of the state array
#define CSize 16 // Size of the ciphertext array
#define PSize 16 // Size of the plaintext array
#define KeySize 16 // Size of the key array
#define Number_of_i ((int)pow(2.0, d)) // Number of plaintexts (max 256 for D=8)
#define Number_of_j ((int)pow(2.0, d)) // Number of states (max 256 for D=8)
#define Number_of_Key ((int)pow(2.0, (2 * d))) // Total number of keys (max 65536 for D=8)
#define Number_of_struct ((int)pow(2.0, (2 * d))) // Number of structures (max 65536 for D=8)
#define bytemin 0 // Minimum byte value for random key generation
#define bytemax 255 // Maximum byte value for random key generation
#define Biclique_Start 8 // Start round for Biclique attack
#define Biclique_End 10 // End round for Biclique attack
#define Biclique_Challenge_Time 10 // Number of iterations for Biclique testing

// Structs to represent the forward and backward states in Biclique operations
typedef struct state_forward {
    uint8_t state0[SSize];
    uint8_t state1[SSize];
    uint8_t state2[SSize];
    uint8_t state3[SSize];
    uint8_t state4[SSize];
    uint8_t state5[SSize];
    uint8_t aftsb1[SSize]; // State after SubBytes
} SF;

typedef struct state_backward {
    uint8_t state15[SSize];
    uint8_t state14[SSize];
    uint8_t state13[SSize];
    uint8_t state12[SSize];
    uint8_t state11[SSize];
    uint8_t state10[SSize];
    uint8_t state9[SSize];
    uint8_t state8[SSize];
    uint8_t state7[SSize];
    uint8_t state6[SSize];
    uint8_t state5[SSize];
} SB;

// Struct to represent the Biclique framework
typedef struct Biclique {
    uint8_t S[SSize];         // Current state
    uint8_t C[CSize];         // Ciphertext
    uint8_t P[PSize];         // Plaintext
    uint8_t BicliqueKey[KeySize]; // Generated key for the Biclique
    uint8_t Delta_i[CSize];   // Differential transitions for plaintext
    uint8_t Nabra_j[SSize];   // Differential transitions for state
    uint8_t subkey[KeySize * 8]; // Precomputed subkeys
    uint8_t candKey[KeySize]; // Candidate key
    uint8_t cmp_P[PSize];     // Comparison plaintext
    uint8_t Vi;               // Current differential i
    uint8_t Vj;               // Current differential j
    SF f_state;               // Forward state
    SB b_state;               // Backward state
    uint8_t cmpflag;          // Flag for key comparison success
} BICL;

// Function prototypes for Biclique operations

/**
 * Initializes a Biclique structure with random data.
 * @param Biclique: Pointer to the Biclique structure.
 * @param seed: Seed for random generation.
 */
void createBiclique(BICL *Biclique, int seed);

/**
 * Generates a random encryption key.
 * @param Key: Pointer to the key array to fill.
 * @param seed: Seed for random generation.
 */
void KeyCreate(uint8_t *Key, int seed);

/**
 * Converts ciphertext to plaintext using a Biclique attack.
 * @param Biclique: Pointer to the Biclique structure.
 * @param secretKey: Pointer to the secret key used for encryption.
 */
void conversion_C2P(BICL *Biclique, uint8_t *secretKey);

/**
 * Precomputes differential transitions from plaintexts.
 * @param Biclique: Pointer to the Biclique structure.
 */
void precompute_P2v(BICL *Biclique);

/**
 * Precomputes differential transitions from states.
 * @param Biclique: Pointer to the Biclique structure.
 */
void precompute_S2v(BICL *Biclique);

/**
 * Recomputes state transitions for verification.
 * @param Biclique: Pointer to the Biclique structure.
 */
void recompute(BICL *Biclique);

/**
 * Performs encryption to generate ciphertext from plaintext and key.
 * @param C: Pointer to the ciphertext array.
 * @param P: Pointer to the plaintext array.
 * @param key: Pointer to the key used for encryption.
 */
void fcompute(uint8_t *C, uint8_t *P, uint8_t *key);

/**
 * Tests candidate keys against known plaintext-ciphertext pairs.
 * @param Biclique: Pointer to the Biclique structure.
 * @param secretKey: Pointer to the actual encryption key.
 */
void testCandidateKeys(BICL *Biclique, uint8_t *secretKey);

/**
 * Generates differential transitions for Biclique attack.
 * @param Biclique: Pointer to the Biclique structure.
 */
void generateDifferentialTransitions(BICL *Biclique);

#endif
