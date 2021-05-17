CC=gcc

wsu-pub-crypt: wsu-pub-crypt.c 
	$(CC) -o wsu-pub-crypt wsu-pub-crypt.c -lm

clean:
	rm -f wsu-pub-crypt
