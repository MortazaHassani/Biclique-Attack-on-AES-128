#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES.h"
#include "Biclique.h"

uint8_t rkey[176];
uint8_t brkey[48];

const uint8_t rcon[] = {
  0x00,0x00,0x00,0x00, /* invalid */
  0x01,0x00,0x00,0x00, /* x^0 */
  0x02,0x00,0x00,0x00, /* x^1 */
  0x04,0x00,0x00,0x00, /* x^2 */
  0x08,0x00,0x00,0x00, /* x^3 */
  0x10,0x00,0x00,0x00, /* x^4 */
  0x20,0x00,0x00,0x00, /* x^5 */
  0x40,0x00,0x00,0x00, /* x^6 */
  0x80,0x00,0x00,0x00, /* x^7 */
  0x1B,0x00,0x00,0x00, /* x^4 + x^3 + x^1 + x^0 */
  0x36,0x00,0x00,0x00, /* x^5 + x^4 + x^2 + x^1 */
};

const uint8_t sbox_table[] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t inv_sbox[] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

void subBytes(uint8_t *state) {
  uint8_t i;
  for (i = 0; i < 16; i++) {
    state[i] = sbox_table[state[i]];
  }
}

void RsubBytes(uint8_t *state, uint8_t *Rtable, int size) {
  uint8_t i;
  for (i = 0; i < size; i++) {
    state[Rtable[i]] = sbox_table[state[Rtable[i]]];
  }
}

static void inv_sub_bytes(uint8_t* state) {
  int i;
  for (i = 0; i < 4 * Nb; i++) {
    state[i] = inv_sbox[state[i]];
  }
}

static void Rinv_sub_bytes(uint8_t* state, uint8_t *Rtable, int size) {
  int i;
  for (i = 0; i < size; i++) {
    state[Rtable[i]] = inv_sbox[state[Rtable[i]]];
  }
}

void shiftRows(uint8_t *state) {
  uint8_t tmp[3];
  uint8_t i, j, a, b;
  tmp[0] = state[1];
  state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp[0];
  tmp[0] = state[2]; tmp[1] = state[6];
  state[2] = state[10]; state[6] = state[14]; state[10] = tmp[0]; state[14] = tmp[1];
  tmp[0] = state[3]; tmp[1] = state[7]; tmp[2] = state[11];
  state[3] = state[15]; state[7] = tmp[0]; state[11] = tmp[1]; state[15] = tmp[2];
}

static void inv_shift_rows(uint8_t* state) {
  uint8_t tmp[3];
  tmp[0] = state[13];
  state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp[0];
  tmp[0] = state[14]; tmp[1] = state[10];
  state[14] = state[6]; state[10] = state[2]; state[6] = tmp[0]; state[2] = tmp[1];
  tmp[0] = state[15]; tmp[1] = state[11]; tmp[2] = state[7];
  state[15] = state[3]; state[11] = tmp[0]; state[7] = tmp[1]; state[3] = tmp[2];
}

void Mixcolumns(uint8_t *state) {
  int i;
  uint8_t tmp[4], *s = state;

  for (i = 0; i < Nb; i++) {
    tmp[0] = gmult(0x02, s[0]) ^ gmult(0x03, s[1]) ^ s[2] ^ s[3];
    tmp[1] = s[0] ^ gmult(0x02, s[1]) ^ gmult(0x03, s[2]) ^ s[3];
    tmp[2] = s[0] ^ s[1] ^ gmult(0x02, s[2]) ^ gmult(0x03, s[3]);
    tmp[3] = gmult(0x03, s[0]) ^ s[1] ^ s[2] ^ gmult(0x02, s[3]);
    memcpy(s, tmp, 4);
    s += 4;
  }
}

static void inv_mix_columns(uint8_t* state) {
  int i;
  uint8_t tmp[4], *s = state;

  for (i = 0; i < Nb; i++) {
    tmp[0] = gmult(0x0e, s[0]) ^ gmult(0x0b, s[1]) ^ gmult(0x0d, s[2]) ^ gmult(0x09, s[3]);
    tmp[1] = gmult(0x09, s[0]) ^ gmult(0x0e, s[1]) ^ gmult(0x0b, s[2]) ^ gmult(0x0d, s[3]);
    tmp[2] = gmult(0x0d, s[0]) ^ gmult(0x09, s[1]) ^ gmult(0x0e, s[2]) ^ gmult(0x0b, s[3]);
    tmp[3] = gmult(0x0b, s[0]) ^ gmult(0x0d, s[1]) ^ gmult(0x09, s[2]) ^ gmult(0x0e, s[3]);
    memcpy(s, tmp, 4);
    s += 4;
  }
}

static uint8_t gmult(uint8_t a, uint8_t b) {
  uint8_t c = 0, i, m;

  for (i = 0; i < 8; i++) {
    if (b & 1)
      c ^= a;

    m = a & 0x80;
    a <<= 1;
    if (m)
      a ^= 0x1b;
    b >>= 1;
  }

  return c;
}

void AddRoundkey(uint8_t *state, uint8_t rcount) {
  uint8_t i;
  for (i = 0; i < 16; i++) {
    state[i] ^= rkey[rcount * 16 + i];
  }
}

void BAddRoundkey(uint8_t *state, uint8_t rcount) {
  uint8_t i;
  for (i = 0; i < 16; i++) {
    state[i] ^= brkey[(rcount - 8) * 16 + i];
  }
}

void KeyExpantion(uint8_t *key) {
    uint8_t i, j;
    uint8_t temp[4];
    for (i = 0; i < 16; i++) {
        rkey[i] = key[i];
    }

    for (i = 4; i < 4 * (Nr + 1); i++) {
        for (j = 0; j < 4; j++) {
            temp[j] = rkey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            xor_Rcon(temp, i);
        }
        for (j = 0; j < 4; j++) {
            rkey[i * 4 + j] = rkey[(i - 4) * 4 + j] ^ temp[j];
        }
    }

    // Debugging output
    // printf("Round keys:\n");
    // for (i = 0; i < 4 * (Nr + 1); i++) {
    //     printf("Round %d: ", i / 4);
    //     for (j = 0; j < 4; j++) {
    //         printf("%x ", rkey[i * 4 + j]);
    //     }
    //     printf("\n");
    // }
}

void invKeyExpantion(uint8_t *key) {
  uint8_t h, i, j, k;
  uint8_t temp[4];
  for (i = 0; i < 16; i++) {
    rkey[i] = key[i];
  }

  for (h = 1; h < Nr + 1; h++) {
    for (i = h * 4 + 3; i > h * 4 - 1; i--) {
      if (i % Nk == 0) {
        for (j = 0; j < 4; j++) {
          temp[j] = rkey[(i + 3) * 4 + j];
        }
        RotWord(temp);
        SubWord(temp);
        xor_Rcon(temp, 4 * (Nr + 1 - h));
      } else {
        for (j = 0; j < 4; j++) {
          temp[j] = rkey[(i - 5) * 4 + j];
        }
      }
      for (j = 0; j < 4; j++) {
        rkey[i * 4 + j] = rkey[(i - 4) * 4 + j] ^ temp[j];
      }
    }
  }
}

void KeyExpantion2(uint8_t *key, uint8_t *Dkey) {
  uint8_t i, j;
  uint8_t temp[4];
  for (i = 0; i < 16; i++) {
    brkey[i] = key[i] ^ Dkey[i];
  }

  for (i = 36; i < 4 * (Nr + 1); i++) {
    for (j = 0; j < 4; j++) {
      temp[j] = brkey[(i - 33) * 4 + j];
    }
    if (i % Nk == 0) {
      RotWord(temp);
      SubWord(temp);
      xor_Rcon(temp, i);
    }
    for (j = 0; j < 4; j++) {
      brkey[(i - 32) * 4 + j] = brkey[(i - 36) * 4 + j] ^ temp[j];
    }
  }
}

void KeyExpantion4(uint8_t *key, uint8_t *bsubkey) {
  uint8_t h, i, j;
  uint8_t temp[4];

  for (i = 0; i < 16; i++) {
    rkey[i] = key[i];
  }

  for (h = 1; h < 8 + 1; h++) {
    for (i = h * 4 + 3; i > h * 4 - 1; i--) {
      if (i % Nk == 0) {
        for (j = 0; j < 4; j++) {
          temp[j] = rkey[(i + 3) * 4 + j];
        }
        RotWord(temp);
        SubWord(temp);
        xor_Rcon(temp, 4 * (8 + 1 - h));
      } else {
        for (j = 0; j < 4; j++) {
          temp[j] = rkey[(i - 5) * 4 + j];
        }
      }
      for (j = 0; j < 4; j++) {
        rkey[i * 4 + j] = rkey[(i - 4) * 4 + j] ^ temp[j];
      }
    }
  }

  for (i = 1; i < 9; i++) {
    for (j = 0; j < 16; j++) {
      bsubkey[(i - 1) * 16 + j] = rkey[i * 16 + j];
    }
  }
}

void KeyRecompute(uint8_t *zsubkey, uint8_t *isubkey, uint8_t *jsubkey, uint8_t *recompsubkey) {
    int i, j;
    uint8_t temp;
    uint8_t cptable[34] = {0, 1, 5, 9, 13, 16, 17, 20, 32, 33, 37, 48, 49, 52, 57, 64, 65, 69, 73, 77, 80, 81, 84, 96, 97, 98, 99, 101, 103, 104, 107, 112, 116, 121};

    memcpy(recompsubkey, isubkey, 128);
    for (i = 0; i < sizeof(cptable); i++) {
        recompsubkey[cptable[i]] = jsubkey[cptable[i]];
    }
    recompsubkey[40] = jsubkey[20] ^ isubkey[24];
    recompsubkey[60] = recompsubkey[40] ^ recompsubkey[44];
    recompsubkey[56] = recompsubkey[40] ^ recompsubkey[36];

    temp = sbox_table[recompsubkey[60]];
    temp ^= rcon[20 + 3];
    recompsubkey[51] = isubkey[35] ^ temp;

    temp = sbox_table[recompsubkey[76]];
    temp ^= rcon[16 + 3];
    recompsubkey[67] = recompsubkey[51] ^ temp;

    // printf("Recomputed subkey: ");
    // for (i = 0; i < 128; i++) {
    //     printf("%x ", recompsubkey[i]);
    // }
    // printf("\n");
}

void RotWord(uint8_t *temp) {
  uint8_t buf;
  buf = temp[0];
  temp[0] = temp[1];
  temp[1] = temp[2];
  temp[2] = temp[3];
  temp[3] = buf;
}

void SubWord(uint8_t *temp) {
  temp[0] = sbox_table[temp[0]];
  temp[1] = sbox_table[temp[1]];
  temp[2] = sbox_table[temp[2]];
  temp[3] = sbox_table[temp[3]];
}

void xor_Rcon(uint8_t *temp, uint8_t i) {
  uint8_t j;
  for (j = 0; j < 4; j++) {
    temp[j] ^= rcon[i + j];
  }
}

void Enc(uint8_t *in, uint8_t *out, int start, int end) {
  uint8_t i, j;
  uint8_t *state = out;
  memcpy(state, in, 16);
  if (!start) {
    AddRoundkey(state, 0);
    start++;
  }

  for (i = start; i < end; i++) {
    subBytes(state);
    shiftRows(state);
    Mixcolumns(state);
    AddRoundkey(state, i);
  }

  if (end == 10) {
    subBytes(state);
    shiftRows(state);
    AddRoundkey(state, i);
  } else if (!end) {

  } else {
    subBytes(state);
    shiftRows(state);
    Mixcolumns(state);
    AddRoundkey(state, i);
  }
}

void BEnc(uint8_t *in, uint8_t *out, int start, int end) {
  uint8_t i, j;
  uint8_t *state = out;
  memcpy(state, in, 16);

  for (i = start; i < end; i++) {
    subBytes(state);
    shiftRows(state);
    Mixcolumns(state);
    BAddRoundkey(state, i);
  }

  subBytes(state);
  shiftRows(state);
  BAddRoundkey(state, i);
}

void PEnc(uint8_t *in, SF *f_state, uint8_t *k) {
  uint8_t i, j;
  uint8_t state[16];

  memcpy(state, in, 16);
  memcpy(f_state->state0, state, 16);
  for (i = 0; i < 16; i++) {
    state[i] ^= k[112 + i];
  }
  memcpy(f_state->state1, state, 16);

  subBytes(state);
  memcpy(f_state->aftsb1, state, 16);
  shiftRows(state);
  Mixcolumns(state);
  memcpy(f_state->state2, state, 16);
  for (i = 0; i < 16; i++) {
    state[i] ^= k[96 + i];
  }
  memcpy(f_state->state3, state, 16);

  subBytes(state);
  shiftRows(state);
  Mixcolumns(state);
  memcpy(f_state->state4, state, 16);
  for (i = 0; i < 16; i++) {
    state[i] ^= k[80 + i];
  }
  memcpy(f_state->state5, state, 16);
}

void RecomputeF(uint8_t *in, SF *f_state, SF *recomp_state, uint8_t *k) {
  uint8_t i, j;
  uint8_t r1[9] = {0, 1, 2, 3, 4, 6, 8, 9, 12};
  uint8_t i1[7] = {5, 7, 10, 11, 13, 14, 15};
  uint8_t r2[4] = {0, 5, 10, 15};
  uint8_t S[16];
  // recomp_state = f_state;

  memcpy(S, in, 16);
  memcpy(recomp_state->state0, S, 16);
  for (i = 0; i < 16; i++) {
    S[i] ^= k[112 + i];
  }
  memmove(recomp_state->state1, S, 16);

  RsubBytes(S, r1, 9);
  for (i = 0; i < 7; i++) {
    S[i1[i]] = f_state->aftsb1[i1[i]];
  }
  shiftRows(S);
  Mixcolumns(S);
  memmove(recomp_state->state2, S, 16);
  for (i = 0; i < 16; i++) {
    S[i] ^= k[96 + i];
  }
  memmove(recomp_state->state3, S, 16);

  RsubBytes(S, r2, 4);
  shiftRows(S);
  Mixcolumns(S);
  memmove(recomp_state->state4, S, 16);
  for (i = 0; i < 16; i++) {
    S[i] ^= k[80 + i];
  }
  memmove(recomp_state->state5, S, 16);
}

void Dec(uint8_t *in, uint8_t *out, int start, int end) {
    uint8_t i, j;
    uint8_t *state = out;
    memcpy(state, in, 16);

    if (start == 10) {
        AddRoundkey(state, start);
        start--;
    }

    for (i = start; i > end; i--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        AddRoundkey(state, i);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    AddRoundkey(state, 0);
}

void Binv_f(uint8_t *in, uint8_t *out, int start, int end) {
  uint8_t i, j;
  uint8_t *state = out;
  // uint8_t Nabra_j_Key[KeySize] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  memcpy(state, in, 16);
  if (start == 10) {
    BAddRoundkey(state, start);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    // start--;
  }

  for (i = start - 1; i >= end; i--) {
    BAddRoundkey(state, i);
    inv_mix_columns(state);
    inv_shift_rows(state);
    inv_sub_bytes(state);
  }
}

void Pinv_f(uint8_t *in, SB *b_state, uint8_t *k) {
  uint8_t i, j;
  uint8_t state[16];

  memmove(state, in, 16);
  memcpy(b_state->state15, state, 16);
  for (i = 0; i < 16; i++) {
    state[i] ^= k[i];
  }
  memcpy(b_state->state14, state, 16);
  inv_mix_columns(state);
  inv_shift_rows(state);
  inv_sub_bytes(state);
  memcpy(b_state->state13, state, 16);

  for (i = 0; i < 16; i++) {
    state[i] ^= k[16 + i];
  }
  memcpy(b_state->state12, state, 16);
  inv_mix_columns(state);
  inv_shift_rows(state);
  inv_sub_bytes(state);
  memcpy(b_state->state11, state, 16);

  for (i = 0; i < 16; i++) {
    state[i] ^= k[32 + i];
  }
  memcpy(b_state->state10, state, 16);
  inv_mix_columns(state);
  inv_shift_rows(state);
  inv_sub_bytes(state);
  memcpy(b_state->state9, state, 16);

  for (i = 0; i < 16; i++) {
    state[i] ^= k[48 + i];
  }
  memcpy(b_state->state8, state, 16);
  inv_mix_columns(state);
  inv_shift_rows(state);
  inv_sub_bytes(state);
  memcpy(b_state->state7, state, 16);

  for (i = 0; i < 16; i++) {
    state[i] ^= k[64 + i];
  }
  memcpy(b_state->state6, state, 16);
  inv_mix_columns(state);
  inv_shift_rows(state);
  inv_sub_bytes(state);
  memcpy(b_state->state5, state, 16);
}

void RecomputeB(uint8_t *in, SB *b_state, SB *recomp_state, uint8_t *k) {
  uint8_t i, j;
  uint8_t S[16];
  uint8_t r7[4] = {2, 7, 8, 13};
  uint8_t r6[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t r5[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t r4[4] = {0, 1, 2, 3};
  uint8_t r3[1] = {0};
  uint8_t i7[12] = {0, 1, 3, 4, 5, 6, 9, 10, 11, 12, 14, 15};

  memcpy(S, in, 16);
  memmove(recomp_state->state15, S, 16);

  for (i = 0; i < 16; i++) {
    S[i] ^= k[i];
  }
  memmove(recomp_state->state14, S, 16);

  inv_mix_columns(S);
  inv_shift_rows(S);
  Rinv_sub_bytes(S, r7, 4);
  for (i = 0; i < 12; i++) {
    S[i7[i]] = b_state->state13[i7[i]];
  }
  memmove(recomp_state->state13, S, 16);

  for (i = 0; i < 16; i++) {
    S[i] ^= k[16 + i];
  }
  memmove(recomp_state->state12, S, 16);
  inv_mix_columns(S);
  inv_shift_rows(S);
  Rinv_sub_bytes(S, r6, 16);
  memmove(recomp_state->state11, S, 16);

  for (i = 0; i < 16; i++) {
    S[i] ^= k[32 + i];
  }
  memmove(recomp_state->state10, S, 16);
  inv_mix_columns(S);
  inv_shift_rows(S);
  Rinv_sub_bytes(S, r5, 16);
  memmove(recomp_state->state9, S, 16);

  for (i = 0; i < 16; i++) {
    S[i] ^= k[48 + i];
  }
  memmove(recomp_state->state8, S, 16);
  inv_mix_columns(S);
  inv_shift_rows(S);
  Rinv_sub_bytes(S, r4, 4);
  memmove(recomp_state->state7, S, 16);

  for (i = 0; i < 16; i++) {
    S[i] ^= k[64 + i];
  }
  memmove(recomp_state->state6, S, 16);
  inv_mix_columns(S);
  inv_shift_rows(S);
  Rinv_sub_bytes(S, r3, 1);
  memmove(recomp_state->state5, S, 16);
}

void validateAESImplementation() {
    uint8_t testPlaintext[PSize] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    uint8_t expectedCiphertext[CSize] = {0xcb, 0x3d, 0x64, 0xd7, 0xce, 0x6f, 0xfd, 0x3f, 
                               0x05, 0xdb, 0x25, 0x33, 0xaa, 0x06, 0xec, 0x09};
    uint8_t testCiphertext[CSize];

    Enc(testPlaintext, testCiphertext, 0, 10);

    if (!memcmp(testCiphertext, expectedCiphertext, CSize)) {
        printf("AES implementation is correct.\n");
    } else {
        printf("AES implementation is incorrect.\n");
        printf("Expected Ciphertext: ");
        for (int i = 0; i < CSize; i++) {
            printf("%02x ", expectedCiphertext[i]);
        }
        printf("\n");
        printf("Actual Ciphertext: ");
        for (int i = 0; i < CSize; i++) {
            printf("%02x ", testCiphertext[i]);
        }
        printf("\n");
    }
}
