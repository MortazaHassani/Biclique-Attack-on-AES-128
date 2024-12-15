# Biclique Attack on AES-128
The biclique attack is an advanced variant of the Meet-in-the-Middle (MITM) attack,
for the cryptanalysis of block ciphers to recover secret keys. It addresses the limitations
of the traditional MITM attack, which is limited in breaking ciphers without independent
key bits. In a biclique attack, the process begins by partitioning all possible secret keys
into groups. For each group, a biclique structure is constructed. This structure helps
in ﬁltering out incorrect keys through partial matching, leaving candidate keys. A valid
plaintext-ciphertext pair (P, C) is used to determine the correct key. Since biclique crypt-
analysis is based on MITM attacks, it is applicable to most block ciphers

# Report
Inside `report` folder make with pdflatex.

# Code
Inside `src` folder make with gcc or just ```c make```
