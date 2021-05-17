WSU Pub Crypt

Files:

	Makefile - makes the executable
	wsu-pub-crypt.c - c code for program
	wsu-pub-crypt - program
	*.txt - example text files

To compile:

	make

To clean:

	make clean

To run:

	./wsu-pub-crypt -genkey (Generate key)
	./wsu-pub-crypt -e -k <public keyfile> -in <plaintext file> -out <cypher text file> (Encrypt)
	./wsu-pub-crypt -d -k <private keyfile> -in <cypher text file> -out <decoded text file (Decrypt)

Example:

	./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt (Encrypt)
	./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt (Decrypt)

