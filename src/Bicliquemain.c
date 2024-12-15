#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES.h"
#include "Biclique.h"

int main(int argc, char *argv[]) {
    int i, j;
    int k, x;
    int flag = 0;
    int count = 0;
    int seed;

    u_int8_t secretKey[KeySize] = {0x23, 0xe3, 0x67, 0x01, 0x42, 0x12, 0xa3, 0xf0, 0xef, 0x22, 0x3a, 0x11, 0xa9, 0x2b, 0x91, 0xcd};
    // u_int8_t secretKey[KeySize] = {0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 
                            //    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //Weak Key for test
    BICL *Biclique;

    Biclique = (BICL *)malloc(sizeof(BICL) * Number_of_struct);

    // seed = atoi(argv[1]);
    seed = 0; // Fixed seed value

    for (x = 0; x < Biclique_Challenge_Time; x++) {
        printf("----Start Biclique----\n");
        for (i = 0; i < Number_of_struct; i++) {
            Biclique[i] = (BICL){0};
        }

        createBiclique(Biclique, seed + x);
        conversion_C2P(Biclique, secretKey);
        precompute_P2v(Biclique);
        precompute_S2v(Biclique);
        recompute(Biclique);

        //// Output results ////
        printf("i = %d j = %d Number_of_Key = %d seed = %d\n", Number_of_i, Number_of_j, Number_of_Key, seed + x);

        printf("----End Biclique----\n");

        printf("----Secret key----\n");
        for (k = 0; k < KeySize - 1; k++) {
            printf("%x,", secretKey[k]);
        }
        printf("%x\n", secretKey[k]);

        printf("----Start Compare----\n");

        // Compare Vi and Vj
        for (i = 0; i < Number_of_struct; i++) {
            if (Biclique[i].Vi == Biclique[i].Vj) {
                printf("Possible key here: ");
                printf("K[%d][%d]\n", i % Number_of_i, i / Number_of_j);
                for (k = 0; k < KeySize - 1; k++) {
                    printf("%x,", Biclique[i].subkey[112 + k]);
                }
                printf("%x\n", Biclique[i].subkey[112 + k]);
                printf("Vi is : %x\t", Biclique[i].Vi);
                printf("Vj is : %x\n", Biclique[i].Vj);
                printf("----\n");
                count++;
                Biclique[i].cmpflag = 1;
            }
        }

        // Test candidate keys
        for (i = 0; i < Number_of_struct; i++) {
            if (Biclique[i].cmpflag) {
                u_int8_t decrypted[PSize];
                fcompute(Biclique[i].C, decrypted, Biclique[i].candKey);

                // Debug: Print the known plaintext
                printf("Known plaintext for K[%d][%d]: ", i % Number_of_i, i / Number_of_j);
                for (k = 0; k < PSize; k++) {
                    printf("%x ", Biclique[i].P[k]);
                }
                printf("\n");

                // Debug: Print the candidate key
                printf("Testing candidate key K[%d][%d]: ", i % Number_of_i, i / Number_of_j);
                for (k = 0; k < KeySize; k++) {
                    printf("%x ", Biclique[i].candKey[k]);
                }
                printf("\n");

                // Debug: Print the decrypted plaintext
                printf("Decrypted plaintext: ");
                for (k = 0; k < PSize; k++) {
                    printf("%x ", decrypted[k]);
                }
                printf("\n");

                // Compare the decrypted plaintext with the known plaintext
                if (!memcmp(Biclique[i].P, decrypted, PSize)) {
                    printf("Secret key found:\n");
                    printf("K[%d][%d]: ", i % Number_of_i, i / Number_of_j);
                    for (k = 0; k < KeySize - 1; k++) {
                        printf("%x,", Biclique[i].candKey[k]);
                    }
                    printf("%x\n", Biclique[i].candKey[k]);
                    free(Biclique); // Free memory before exiting
                    exit(0);
                }
            }
        }

        if (!flag) {
            printf("There's no secret key in here\n");
        } else {
            free(Biclique); // Free memory before exiting
            exit(0);
        }

        printf("count is %d\n", count);
        count = 0;
    }
    /*
    Verification of AES Implementation Note: Seed dependant
    */
    // validateAESImplementation(); 

    free(Biclique);
}
