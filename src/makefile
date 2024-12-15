Biclique: Bicliquemain.o Biclique.o AES.o
	gcc -g -o Biclique Bicliquemain.o Biclique.o AES.o

Bicliqueouttest: Bicliquemain.o Bicliqueoutputtest.o AESoutputtest.o
	gcc -o Bicliqueouttest Bicliquemain.o Bicliqueoutputtest.o AESoutputtest.o

Bicliquemain.o: Bicliquemain.c Biclique.h
	gcc -c Bicliquemain.c -lm

Biclique.o: Biclique.c AES.h Biclique.h
	gcc -c Biclique.c -lm

AES.o: AES.c AES.h
	gcc -c AES.c

AESoutputtest.o: AESoutputtest.c AES.h
	gcc -c AESoutputtest.c

Bicliqueoutputtest.o: Bicliqueoutputtest.c Biclique.h
	gcc -c Bicliqueoutputtest.c -lm

test: Biclique
	./Biclique

out10: Bicliqueouttest
	./Bicliqueouttest

clean:
	rm -f *.o Biclique