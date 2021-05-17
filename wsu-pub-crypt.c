#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

// atoi_64
// 	function returns a int representation of string "a"
uint64_t atoi_64(char * a){
	int i, len;
	uint64_t result = 0;

	len = strlen(a); // length of input string

	for (i = 0; i < len; i++) {
		if ((a[i] - '0') < 0 || (a[i] - '0') > 9) // error non integer input
			return -1;
		result = result * 10 + ( a[i] - '0' ); // convert to an int
	}
	return result;
}

// modular exponentation multiply
uint64_t modular_exponentation_multiply(__uint128_t a, __uint128_t b, uint64_t mod) {
    if (b < (mod / a)) return (a*b) % mod; // base case

    uint64_t return_value = 0; // return value

    a = a % mod; // a & mod value

    while (b > 0) { // while exponent >0
        if ((b & 1) == 1) {
            return_value = (return_value + a) % mod;
        }
        a = (a<<1) % mod;
        b >>= 1;
    }
    return return_value;
}

// function generates random number with 32nd-bit high
uint64_t rand_32nd_bit_high() {
  	uint64_t r = rand();
  	if (r < 2147483648) // if 32nd bit isn't high, Add 2^32.
		r+=2147483648;
  	return r;
}

// modular exponentation of (a^b) mod n
uint64_t modular_exponentation(__uint128_t a, __uint128_t b, __uint128_t n){
	uint64_t return_value = 1;

    while (b > 0) { // while exponent >0
        if ((b & 1) == 1) { // if b == 0
            return_value = (return_value * a) % n;
        }
        a = (a * a) % n; // a = a^2 mod n
        b >>= 1; // shift right b
    }
    return return_value;  
}

int witness(uint64_t a, uint64_t n) {
	uint64_t t = 1, u, x_prev, x;

    // get t where it's >= 1 and u is odd
    for(;;t++) {
        u = (n - 1) / (uint64_t)pow(2, t); // getting u
        if((u % 2) != 0)   				   // done
            break;
    }

    // get starting x value
    x_prev = modular_exponentation(a, u, n);

    for(uint64_t i = 1; i <= t; i++) {
        x = (x_prev * x_prev) % n; // x = (x-1)^2 mod n
        if((x == 1) && (x_prev != 1) && (x_prev != (n - 1)))
            return 0; // composite
        x_prev = x; // next x
    }
    if(x != 1)
        return 0; // composite

    return 1; // prime
}

// function uses the miller rabin algo. to check if number "n" is prime
int miller_rabin(uint64_t n, uint64_t a, uint64_t s) {
	if (s == -1) { // if just one test case
		if (witness(a, n) == 1) // run once
			return 1; // prime
	} else {
		for (s = s; s > 0; s--) { // run for s number of test cases
			uint64_t random_witness = rand_32nd_bit_high() % n;
			if (witness(random_witness, n) == 1)
				return 1; // prime
		}
	}
	return 0; // composite
}

// function generates a private / public key into pubkey.txt / prikey.txt
int generate_key() {
	uint32_t random_prime, p, q, d, e_2;
	FILE *fp;

	srand(time(NULL)); // initalize time variable

	// while we dont have prime p and generator q
	while (1) {
		random_prime = (rand_32nd_bit_high() / 2) + 1; // get a random q
		p = (2 * random_prime) + 1;					   // calculate p from q

		// if p and q are prime q is a generator of p, break
		if (miller_rabin(random_prime, 0, 10) == 1 && (random_prime % 12 == 5) && miller_rabin(p, 0, 10) == 1)
			break;
	}

	q = 2;
	d = rand_32nd_bit_high() % p;
	e_2 = modular_exponentation(q, d, p);

	printf("p:   %" PRIu32 "\nq:   %" PRIu32 "\nd:   %" PRIu32 "\ne_2: %" PRIu32 "\n", p, q, d, e_2);

	// make a new file pubkey.txt
	fp = fopen("pubkey.txt", "w+");
	if (fp == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// add publickey to pubkey.txt
	fprintf(fp, "%" PRIu32 " %" PRIu32 " %" PRIu32 "\n", p, q, e_2);

	fclose(fp); // close pubkey.txt

	// make a new file prikey.txt
	fp = fopen("prikey.txt", "w+");
	if (fp == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// add private key to prikey.txt
	fprintf(fp, "%" PRIu32 " %" PRIu32 " %" PRIu32 "\n", p, q, d);

	fclose(fp); // close prikey.txt

	return 0;
}

int encode(char *in, char *out, char *key) {
	uint64_t p, g, e_2, C_1, C_2, C_2_a, C_2_b, k, m;
	FILE *fp_key, *fp_in, *fp_out;
	char buffer[64], c, m_1 = 0, m_2 = 0, m_3 = 0, m_4 = 0;

	// open keyfile
	fp_key = fopen(key, "r");
	if (fp_key == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// get prime p from keyfile
	printf("Prime: ");
	fscanf(fp_key, " %1023s", buffer); 
	puts(buffer); 
	p = atoi_64(buffer);

	// get generator g from keyfile
	printf("Generator: ");
	fscanf(fp_key, " %1023s", buffer);
	puts(buffer);
	g = atoi_64(buffer);

	// get e_2 from keyfile
	printf("E_2: ");
	fscanf(fp_key, " %1023s", buffer);
	puts(buffer);
	e_2 = atoi_64(buffer);

	fclose(fp_key); // close keyfile

	// open input file
	fp_in = fopen(in, "r");
	if (fp_in == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// open output file
	fp_out = fopen(out, "w+");
	if (fp_out == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	while (1) {

		for (int i = 0; i < 4; i++) {

			if ((c = fgetc(fp_in)) == EOF) {
				break;
			}

			// get 4 bytes
			if (i == 0)
				m_1 = c;
			if (i == 1)
				m_2 = c;
			if (i == 2)
				m_3 = c;
			if (i == 3)
				m_4 = c;
				
			// if got 4 bytes
			if (i == 3) {

				// concatenate to make a 31-bit m
				// since most significant bit will be zero 
				m = (m_1) | (m_2 << 8) | ( m_3 << 16 ) | (m_4 << 24);
				
				k = rand_32nd_bit_high() % p; // get random value k (0 - (p-1))
				C_1 = modular_exponentation(g, k, p); // get C_1 =  (g^k) mod p
				
				// get C_2 = ((e_2^k) * char) mod p = (((e_2 ^ k) mod p) * ((char ^ 1) mod p)) mod p
				C_2_a = modular_exponentation(e_2, k, p); // e_2 ^ k mod p
				C_2_b = modular_exponentation(m, 1, p);	// char ^ 1 mod p
				C_2 = modular_exponentation(C_2_a * C_2_b, 1, p);

				printf("C_1: %" PRId64 "    C_2: %" PRId64 "\n", C_1, C_2); // print results
				fprintf(fp_out, "%" PRId64 " %" PRId64 "\n", C_1, C_2); // output key pair C_1 C_2 to output file

				m_1 = 0;
				m_2 = 0;
				m_3 = 0;
				m_4 = 0;
			}
		}	

		
		if (c == EOF) {

			// if there are still chars left to encode
			if (m_1 != 0 || m_2 != 0 || m_3 != 0 || m_4 != 0) {

				// concatenate to make a 31-bit m
				// since most significant bit will be zero 
				m = (m_1 << 24) | (m_2 << 16) | ( m_3 << 8 ) | (m_4);
				
				k = rand_32nd_bit_high() % p; // get random value k (0 - (p-1))
				C_1 = modular_exponentation(g, k, p); // get C_1 =  (g^k) mod p
				
				// get C_2 = ((e_2^k) * char) mod p = (((e_2 ^ k) mod p) * ((char ^ 1) mod p)) mod p
				C_2_a = modular_exponentation(e_2, k, p); // e_2 ^ k mod p
				C_2_b = modular_exponentation(m, 1, p);	// char ^ 1 mod p

				C_2 = modular_exponentation(C_2_a * C_2_b, 1, p); 

				printf("C_1: %" PRId64 "    C_2: %" PRId64 "\n", C_1, C_2);
				fprintf(fp_out, "%" PRId64 " %" PRId64 "\n", C_1, C_2); // output key pair C_1 C_2 to output file
			}
			break;
		}
	}

	fclose(fp_in); // close input file
	fclose(fp_out); // close output file

	return 0;

}

int decode(char *in, char *out, char *key) {
	uint64_t p, g, d, C_1, C_2, C_1_temp, C_2_temp, k, m;
	FILE *fp_key, *fp_in, *fp_out;
	char buffer[64], c, m_1, m_2, m_3, m_4;

	// open keyfile
	fp_key = fopen(key, "r");
	if (fp_key == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// get prime p from keyfile
	printf("Prime: ");
	fscanf(fp_key, " %1023s", buffer); 
	puts(buffer); 
	p = atoi_64(buffer);

	// get generator g from keyfile
	printf("Generator: ");
	fscanf(fp_key, " %1023s", buffer);
	puts(buffer);
	g = atoi_64(buffer);

	// get e_2 from keyfile
	printf("D: ");
	fscanf(fp_key, " %1023s", buffer);
	puts(buffer);
	d = atoi_64(buffer);

	fclose(fp_key); // close keyfile

	// open input file
	fp_in = fopen(in, "r");
	if (fp_in == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	// open output file
	fp_out = fopen(out, "w+");
	if (fp_out == NULL){
		printf("Error opening file!\n");
		return 1;
	}

	while ((fscanf(fp_in, " %1023s", buffer)) > 0) { // for each char in input file

		// get c_1
		puts(buffer);
		C_1 = atoi_64(buffer);

		// get c_2
		fscanf(fp_in, " %1023s", buffer);
		puts(buffer);
		C_2 = atoi_64(buffer);

		// get c_1 mod exp. value
		C_1_temp = modular_exponentation(C_1, p-1-d, p);

		// get c_2 mod exp. value
		C_2_temp = modular_exponentation(C_2, 1, p);

		// get 64 bit plaintext
		m = modular_exponentation_multiply(C_1_temp, C_2_temp, p);
		
		// extract 8-bit chars
		m_4 = (m & 0xff000000UL) >> 24;
		m_3 = (m & 0x00ff0000UL) >> 16;
		m_2 = (m & 0x0000ff00UL) >> 8;
		m_1 = (m & 0x000000ffUL);

		// print chars if not zeros
		if (m_1 != 0) {
			fprintf(fp_out,"%c", m_1);
		}
			
		if (m_2 != 0) {
			fprintf(fp_out,"%c", m_2);
		}
			
		if (m_3 != 0) {
			fprintf(fp_out,"%c", m_3);
		}
			
		if (m_4 != 0) {
			fprintf(fp_out,"%c", m_4);
		}
	}

	// print result
	printf("Decrypted result:\n");
	fseek(fp_out, 0, SEEK_SET);
	while ((c = fgetc(fp_out)) != EOF) {
		printf("%c", c);
	}

	fclose(fp_in); // close input file
	fclose(fp_out); // close output file

	return 0;

}

int main(int argc, char * argv[]){
	int status = 0, encoding = 0, decoding = 0, genkey = 0;
	char key[128], in[128], out[128];

	// ERROR: wrong arguments
	if (argc != 2 && argc != 8) {
		printf("ERROR: Not enough arguments\ncorrect arguments example:\n./wsu-pub-crypt -genkey\n./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt\n./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt\n");
        printf("argc = %d\n", argc);
        return 0;
	}

	//
	//	Parse argv for input arguments
	//
    for (int i = 0; i < argc; ++i) { 

        // keygen flag
		if (strcmp(argv[i], "-genkey") == 0) genkey = 1;

		// encoding flag
		if (strcmp(argv[i], "-e") == 0) encoding = 1;

		// decoding flag
		if (strcmp(argv[i], "-d") == 0) decoding = 1;

		// key file
		if (strcmp(argv[i], "-k") == 0)
			strcpy(key, argv[i+1]);

		// input file
		if (strcmp(argv[i], "-in") == 0)
			strcpy(in, argv[i+1]);

		// output file
		if (strcmp(argv[i], "-out") == 0)
			strcpy(out, argv[i+1]);

    }

	// ERROR: wrong genkey, encoding, or decoding arguments
	if ((encoding == 1 && decoding == 1) || (genkey == 1) && (encoding == 1 || decoding == 1)) {
        printf("ERROR: Incorrect arguments\ncorrect arguments example:\n./wsu-pub-crypt -genkey\n./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt\n./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt\n");
		return 0;
	}

    //
	//	Generate key
	//
	if (genkey == 1) {
		status = generate_key();
	}

	//
	//	Encoding
	//
	if (encoding == 1) {
		status = encode(in, out, key);
	}

	//
	// Decoding
	//
	if (decoding == 1) {
        status = decode(in, out, key);
	}

	// ERROR: failed to encode / decode
	if (status == 1) {
		printf("Program failed to execute\n");
	} else {
		printf("Program executed sucessfully\n");
	}

	return 0;

}