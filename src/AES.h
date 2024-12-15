#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include "Biclique.h"

// Constants defining AES parameters
#define Nk 4   // Number of 32-bit words in the key (128-bit key for AES-128)
#define Nr 10  // Number of rounds for AES-128
#define Nb 4   // Number of 32-bit words in the state (4x4 bytes = 128 bits)

// Function prototypes for AES operations

/**
 * Applies the SubBytes transformation to the state using the S-box.
 * @param state: Pointer to the current state array (4xNb bytes).
 */
void subBytes(uint8_t *state);

/**
 * Reverses the SubBytes transformation using a custom reverse table.
 * @param state: Pointer to the current state array.
 * @param Rtable: Pointer to the reverse transformation table.
 * @param size: Size of the reverse table.
 */
void RsubBytes(uint8_t *state, uint8_t *Rtable, int size);

/**
 * Applies the inverse SubBytes transformation to the state.
 * @param state: Pointer to the current state array.
 */
static void inv_sub_bytes(uint8_t* state);

/**
 * Reverses the inverse SubBytes transformation using a custom reverse table.
 * @param state: Pointer to the current state array.
 * @param Rtable: Pointer to the reverse transformation table.
 * @param size: Size of the reverse table.
 */
static void Rinv_sub_bytes(uint8_t* state, uint8_t *Rtable, int size);

/**
 * Performs the ShiftRows transformation on the state.
 * @param state: Pointer to the current state array.
 */
void shiftRows(uint8_t *state);

/**
 * Performs the inverse of the ShiftRows transformation on the state.
 * @param state: Pointer to the current state array.
 */
static void inv_shift_rows(uint8_t* state);

/**
 * Performs the MixColumns transformation on the state.
 * @param state: Pointer to the current state array.
 */
void Mixcolumns(uint8_t *state);

/**
 * Performs the inverse MixColumns transformation on the state.
 * @param state: Pointer to the current state array.
 */
static void inv_mix_columns(uint8_t* state);

/**
 * Multiplies two bytes in the GF(2^8) finite field.
 * @param a: The first byte.
 * @param b: The second byte.
 * @return Result of multiplication in GF(2^8).
 */
static uint8_t gmult(uint8_t a, uint8_t b);

/**
 * Adds the round key to the state.
 * @param state: Pointer to the current state array.
 * @param rcount: The round number to select the correct round key.
 */
void AddRoundkey(uint8_t *state, uint8_t rcount);

/**
 * Adds the biclique round key to the state.
 * @param state: Pointer to the current state array.
 * @param rcount: The round number to select the correct round key.
 */
void BAddRoundkey(uint8_t *state, uint8_t rcount);

/**
 * Expands the encryption key for all AES rounds.
 * @param key: Pointer to the original key (Nk * 4 bytes).
 */
void KeyExpantion(uint8_t *key);

/**
 * Expands the decryption key for all AES rounds.
 * @param key: Pointer to the original key (Nk * 4 bytes).
 */
void invKeyExpantion(uint8_t *key);

/**
 * Rotates a 4-byte word left by one byte.
 * @param temp: Pointer to the word to rotate.
 */
void RotWord(uint8_t *temp);

/**
 * Applies the SubBytes transformation to a 4-byte word.
 * @param temp: Pointer to the word to transform.
 */
void SubWord(uint8_t *temp);

/**
 * XORs the word with the round constant.
 * @param temp: Pointer to the word.
 * @param i: Round number.
 */
void xor_Rcon(uint8_t *temp, uint8_t i);

/**
 * Key schedule for biclique generation.
 * @param key: Pointer to the original key.
 * @param Dkey: Pointer to the derived key.
 */
void KeyExpantion2(uint8_t *key, uint8_t *Dkey);

/**
 * Key schedule for biclique precomputations.
 * @param key: Pointer to the original key.
 * @param frkey: Pointer to the forward round keys.
 */
void KeyExpantion3(uint8_t *key, uint8_t *frkey);

/**
 * Key schedule for biclique backward computations.
 * @param key: Pointer to the original key.
 * @param brkey: Pointer to the backward round keys.
 */
void KeyExpantion4(uint8_t *key, uint8_t *brkey);

/**
 * Recomputes a subkey from other subkeys.
 * @param zsubkey: Pointer to subkey Z.
 * @param isubkey: Pointer to subkey I.
 * @param jsubkey: Pointer to subkey J.
 * @param recompsubkey: Pointer to the recomputed subkey.
 */
void KeyRecompute(uint8_t *zsubkey, uint8_t *isubkey, uint8_t *jsubkey, uint8_t *recompsubkey);

/**
 * Encrypts input data using AES.
 * @param in: Pointer to the input data.
 * @param out: Pointer to the output data.
 * @param start: Start round of encryption.
 * @param end: End round of encryption.
 */
void Enc(uint8_t *in, uint8_t *out, int start, int end);

/**
 * Encrypts data using biclique-based AES.
 * @param in: Pointer to the input data.
 * @param out: Pointer to the output data.
 * @param start: Start round of encryption.
 * @param end: End round of encryption.
 */
void BEnc(uint8_t *in, uint8_t *out, int start, int end);

/**
 * Precomputes encryption state for biclique.
 * @param in: Pointer to the input data.
 * @param f_state: Pointer to the forward state structure.
 * @param k: Pointer to the key.
 */
void PEnc(uint8_t *in, SF *f_state, uint8_t *k);

/**
 * Recomputes forward encryption state for biclique.
 * @param in: Pointer to the input data.
 * @param f_state: Pointer to the forward state structure.
 * @param recomp_state: Pointer to the recomputed state structure.
 * @param k: Pointer to the key.
 */
void RecomputeF(uint8_t *in, SF *f_state, SF *recomp_state, uint8_t *k);

/**
 * Decrypts input data using AES.
 * @param in: Pointer to the input data.
 * @param out: Pointer to the output data.
 * @param start: Start round of decryption.
 * @param end: End round of decryption.
 */
void Dec(uint8_t *in, uint8_t *out, int start, int end);

/**
 * Performs biclique-based decryption.
 * @param in: Pointer to the input data.
 * @param out: Pointer to the output data.
 * @param start: Start round of decryption.
 * @param end: End round of decryption.
 */
void Binv_f(uint8_t *in, uint8_t *out, int start, int end);

/**
 * Precomputes decryption state for biclique.
 * @param in: Pointer to the input data.
 * @param b_state: Pointer to the backward state structure.
 * @param k: Pointer to the key.
 */
void Pinv_f(uint8_t *in, SB *b_state, uint8_t *k);

/**
 * Recomputes backward decryption state for biclique.
 * @param in: Pointer to the input data.
 * @param b_state: Pointer to the backward state structure.
 * @param recomp_state: Pointer to the recomputed state structure.
 * @param k: Pointer to the key.
 */
void RecomputeB(uint8_t *in, SB *b_state, SB *recomp_state, uint8_t *k);

/**
 * Validates the AES implementation with test vectors.
 */
void validateAESImplementation();

#endif
