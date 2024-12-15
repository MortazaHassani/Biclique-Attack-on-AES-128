#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES.h"
#include "Biclique.h"

void KeyCreate(u_int8_t *Key, int seed) {
    srand(seed);
    for (int i = 0; i < KeySize; i++) {
        Key[i] = bytemin + (int)(rand() * (bytemax - bytemin + 1.0) / (1.0 + RAND_MAX));
    }
}

void createBiclique(BICL *Biclique, int seed) {
    int i, j, k, l, m, a;
    u_int8_t Delta_i_Key[KeySize] = {0};
    u_int8_t Nabra_j_Key[KeySize] = {0};

    KeyCreate(Biclique[0].BicliqueKey, seed);
    KeyExpantion2(Biclique[0].BicliqueKey, Nabra_j_Key);

    Binv_f(Biclique[0].C, Biclique[0].S, Biclique_End, Biclique_Start);

    for (i = 0; i < Number_of_i; i++) {
        Delta_i_Key[8] = i;
        Delta_i_Key[12] = i;

        KeyExpantion2(Biclique[0].BicliqueKey, Delta_i_Key);
        BEnc(Biclique[0].S, Biclique[i].C, Biclique_Start, Biclique_End);

        for (m = 1; m < Number_of_i; m++) {
            memcpy(Biclique[i + m * Number_of_i].C, Biclique[i].C, CSize);
        }
    }

    for (j = 0; j < Number_of_j; j++) {
        Nabra_j_Key[1] = j;
        Nabra_j_Key[9] = j;

        KeyExpantion2(Biclique[0].BicliqueKey, Nabra_j_Key);
        Binv_f(Biclique[0].C, Biclique[j * Number_of_j].S, Biclique_End, Biclique_Start);

        for (m = 0; m < Number_of_j; m++) {
            memcpy(Biclique[j * Number_of_j + m].S, Biclique[j * Number_of_j].S, SSize);
        }
    }

    for (j = 0; j < Number_of_j; j++) {
        Nabra_j_Key[1] = j;
        Nabra_j_Key[9] = j;
        for (i = 0; i < Number_of_i; i++) {
            Delta_i_Key[8] = i;
            Delta_i_Key[12] = i;
            memcpy(Biclique[j * Number_of_j + i].BicliqueKey, Biclique[0].BicliqueKey, 16);
            Biclique[j * Number_of_j + i].Nabra_j[1] = Nabra_j_Key[1];
            Biclique[j * Number_of_j + i].Nabra_j[9] = Nabra_j_Key[9];
            Biclique[j * Number_of_j + i].Delta_i[8] = Delta_i_Key[8];
            Biclique[j * Number_of_j + i].Delta_i[12] = Delta_i_Key[12];
            Biclique[j * Number_of_j + i].BicliqueKey[1] = Biclique[0].BicliqueKey[1] ^ Nabra_j_Key[1];
            Biclique[j * Number_of_j + i].BicliqueKey[9] = Biclique[0].BicliqueKey[9] ^ Nabra_j_Key[9];
            Biclique[j * Number_of_j + i].BicliqueKey[8] = Biclique[0].BicliqueKey[8] ^ Delta_i_Key[8];
            Biclique[j * Number_of_j + i].BicliqueKey[12] = Biclique[0].BicliqueKey[12] ^ Delta_i_Key[12];
        }
    }
}

void conversion_C2P(BICL *Biclique, u_int8_t *secretKey) {
    int i, m;

    KeyExpantion(secretKey);
    for (i = 0; i < Number_of_i; i++) {
        Dec(Biclique[i].C, Biclique[i].P, Biclique_End, 0);
        for (m = 1; m < Number_of_i; m++) {
            memcpy(Biclique[i + m * Number_of_i].P, Biclique[i].P, PSize);
        }
    }
}

void precompute_P2v(BICL *Biclique) {
    int i, c;
    printf("precompare_P2v start\n");
    for (i = 0; i < Number_of_i; i++) {
        KeyExpantion4(Biclique[i].BicliqueKey, Biclique[i].subkey);
        for (c = 0; c < KeySize; c++) {
            Biclique[i].candKey[c] = Biclique[i].subkey[112 + c];
        }
        PEnc(Biclique[i].P, &Biclique[i].f_state, Biclique[i].subkey);
        Biclique[i].Vi = Biclique[i].f_state.state5[0];
    }
}

void precompute_S2v(BICL *Biclique) {
    int j, c;
    printf("precompare_S2v start\n");
    for (j = 0; j < Number_of_j; j++) {
        KeyExpantion4(Biclique[j * Number_of_j].BicliqueKey, Biclique[j * Number_of_j].subkey);
        for (c = 0; c < KeySize; c++) {
            Biclique[j * Number_of_j].candKey[c] = Biclique[j * Number_of_j].subkey[112 + c];
        }
        Pinv_f(Biclique[j * Number_of_j].S, &Biclique[j * Number_of_j].b_state, Biclique[j * Number_of_j].subkey);
        Biclique[j * Number_of_j].Vj = Biclique[j * Number_of_j].b_state.state5[0];
    }
}

void recompute(BICL *Biclique) {
    int i, j, c;

    for (i = 1; i < Number_of_i; i++) {
        for (j = 1; j < Number_of_j; j++) {
            KeyRecompute(Biclique[0].subkey, Biclique[i].subkey, Biclique[j * Number_of_j].subkey, Biclique[i + j * Number_of_j].subkey);
            for (c = 0; c < KeySize; c++) {
                Biclique[i + j * Number_of_j].candKey[c] = Biclique[i + j * Number_of_j].subkey[112 + c];
            }
        }
    }

    printf("recompare_P2v start\n");

    for (i = 0; i < Number_of_i; i++) {
        for (j = 1; j < Number_of_j; j++) {
            RecomputeF(Biclique[i].P, &Biclique[i].f_state, &Biclique[i + j * Number_of_j].f_state, Biclique[i + j * Number_of_j].subkey);
            Biclique[i + j * Number_of_j].Vi = Biclique[i + j * Number_of_j].f_state.state5[0];
        }
    }

    printf("recompare_S2v start\n");

    for (j = 0; j < Number_of_j; j++) {
        for (i = 1; i < Number_of_i; i++) {
            RecomputeB(Biclique[j * Number_of_j].S, &Biclique[j * Number_of_j].b_state, &Biclique[j * Number_of_j + i].b_state, Biclique[j * Number_of_j + i].subkey);
            Biclique[j * Number_of_j + i].Vj = Biclique[j * Number_of_j + i].b_state.state5[0];
        }
    }
}

void fcompute(u_int8_t *C, u_int8_t *P, u_int8_t *key) {
    KeyExpantion(key);
    Dec(C, P, 10, 0);
}

void testCandidateKeys(BICL *Biclique, u_int8_t *secretKey) {
    int i, j, k;
    int flag = 0;

    for (i = 0; i < Number_of_struct; i++) {
        if (Biclique[i].cmpflag) {
            fcompute(Biclique[i].C, Biclique[i].cmp_P, Biclique[i].candKey);
            if (!memcmp(Biclique[i].P, Biclique[i].cmp_P, PSize)) {
                printf("Secret key found: K[%d][%d]\n", i % Number_of_i, i / Number_of_j);
                for (k = 0; k < KeySize - 1; k++) {
                    printf("%x,", Biclique[i].candKey[k]);
                }
                printf("%x\n", Biclique[i].candKey[k]);
                flag = 1;
                break; // Exit once the secret key is found
            }
        }
    }

    if (!flag) {
        printf("No secret key found.\n");
    }
}

void generateDifferentialTransitions(BICL *Biclique) {
    int i, j;
    u_int8_t Delta_i_Key[KeySize] = {0};
    u_int8_t Nabra_j_Key[KeySize] = {0};

    for (i = 0; i < Number_of_i; i++) {
        Delta_i_Key[8] = i;
        Delta_i_Key[12] = i;
        KeyExpantion2(Biclique[0].BicliqueKey, Delta_i_Key);
    }

    for (j = 0; j < Number_of_j; j++) {
        Nabra_j_Key[1] = j;
        Nabra_j_Key[9] = j;
        KeyExpantion2(Biclique[0].BicliqueKey, Nabra_j_Key);
    }
}
