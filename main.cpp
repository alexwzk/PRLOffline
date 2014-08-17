/*
 * Offline Process of the Approximate Private Record Linkage Protocol
 * Created by Zikai (Alex) Wen on 01/06/2013
 * Copyright (c) 2013 Zikai (Alex) Wen. All rights reserved.
 */

//User Library
#include "src/murmurHash3.h"

//Standard Library
#include <set>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <climits>

#if defined(__APPLE__)
#include <sys/time.h>
#else
#include <malloc.h>
#endif

//OpenSSL Library
#include <openssl/sha.h>

//Define Macro
#define NUM_TWO_QUANTUM 1296 //36^2
#define LEN_STR 500
#define NUM_STRID 100
#define LEN_SHA1 20
#define EXE_SUCCESS 0
#define MALLOC_FAILED -1
#define INPUT_INVALID -2

//Functions pretype
int returnQuantumIndex(char former_c, char latter_c);
int convertAlphaHashsToSHA1(unsigned char* dest, uint32_t* source,
		unsigned int id_betaHash, size_t num_alphaHash);
int sha1Cmp(const unsigned char* pre_sha1, const unsigned char* suf_sha1);

//Self-defined Struct
struct AlphaHashs {
	unsigned char sha1_value[LEN_SHA1];
	mutable int str_index[NUM_STRID];
	mutable int str_pos;
	AlphaHashs() {
		str_pos = 0;
	}
	AlphaHashs(unsigned char* new_sha1, unsigned int str_id) {
		memcpy(sha1_value, new_sha1, LEN_SHA1);
		str_pos = 0;
		str_index[str_pos++] = str_id;
	}
	bool operator <(const AlphaHashs &cmp) const {
		if (sha1Cmp(this->sha1_value, cmp.sha1_value) < 0) {
			return true;
		} else {
			return false;
		}
	}
	bool operator ==(const AlphaHashs &cmp) const {
		if (sha1Cmp(this->sha1_value, cmp.sha1_value) == 0) {
			return true;
		} else {
			return false;
		}
	}
	bool operator >(const AlphaHashs &cmp) const {
		if (sha1Cmp(this->sha1_value, cmp.sha1_value) > 0) {
			return true;
		} else {
			return false;
		}
	}
};

int main(int argc, char* argv[]) {
	/*Variables*/
	size_t num_hashFunc = 0;					 //# of hash seed
	size_t num_str = 0;							 //# of strings
	size_t num_alphaHash = 0;					 //# of alpha
	size_t num_betaHash = 0;					 //# of beta
	uint32_t* seed;							//to pick a hash function at random
	uint32_t** hash_matrix;					//hash Matrix [36^2][num_hashFunc]
	uint32_t* minHash_perStr;
	unsigned char sha1_perStr[LEN_SHA1];
	bool to_clean_data = false;
	std::string orig_path;					//The file path of orig_data excluding suffix
	std::ifstream orig_data;				//Original Data of personal info
	std::ofstream hashtables;				//LSH Hashtables to be encoded into a BF or GBF of OBI

	//int t_start, t_end, t_elapsed;			//time tracking
	std::vector<std::set<int> > str_quantums;	//arrayters of string quantums
	std::set<AlphaHashs> alpha_binSet;			// A binSet of alpha hashs

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			num_alphaHash = strtoul(argv[i + 1], NULL, 10);
		} else if (strcmp(argv[i], "-b") == 0) {
			num_betaHash = strtoul(argv[i + 1], NULL, 10);
		} else if (strcmp(argv[i], "-f") == 0) {
			orig_data.open(argv[i + 1]);
			orig_path = std::string(argv[i + 1]).substr(0,
					std::string(argv[i + 1]).find("."));
		} else if (strcmp(argv[i], "-c") == 0) {
			to_clean_data = true;
		}
	}

	if (orig_data.bad()) {
		perror("Error @ File operation. Can't open file. \n");
		exit(INPUT_INVALID);
	}

	num_hashFunc = num_alphaHash * num_betaHash;
	if (num_hashFunc == 0) {
		perror(
				"Error @ Arguments. At least one of Alpha and Beta values is not set. \n");
		exit(INPUT_INVALID);
	}

	seed = (uint32_t*) malloc(sizeof(uint32_t) * num_hashFunc);
	if (!seed) {
		perror("Error @ Seed array memalloc failed. \n");
		exit(MALLOC_FAILED);
	}
	//srand(time(NULL));
	for (unsigned int i = 0; i < num_hashFunc; i++) {
		//seed[i] = rand();
		//!!! Apply the same (rand) hash functions to both sets.
		seed[i] = i;
	}

	str_quantums.reserve(num_str);
	if (str_quantums.capacity() != num_str) {
		perror("Error @ Vector of sets memalloc failed. \n");
		exit(MALLOC_FAILED);
	}

	std::string tmp_str, format_str;
	std::set<int> tmp_set;
	int tmp_quanID;
	char test_char;
	while (std::getline(orig_data, tmp_str)) {
		++num_str;
		tmp_set.clear();

		if (to_clean_data) {
			// Format the string, only accept alphabets and numbers
			format_str.clear();
			for (int i = 0; i < tmp_str.length(); i++) {
				test_char = tmp_str.at(i);
				if ((test_char >= '0' && test_char <= '9')
						|| (test_char >= 'a' && test_char <= 'z')) {
					format_str += test_char;
				}
			}
			tmp_str = format_str;
		}

		for (unsigned int j = 1; j < tmp_str.length(); j++) {
			//j refers to the latter char of 2-quantum
			if (tmp_set.size() == tmp_set.max_size()) {
				perror("Error @ Temporary set insert failed. \n");
				exit(MALLOC_FAILED);
			}
			tmp_quanID = returnQuantumIndex(tmp_str.at(j - 1), tmp_str.at(j));
			if (tmp_quanID == INPUT_INVALID) {
				perror("Error @ Invalid inputs in returnQuantumIndex.\n");
				printf("%lu \n", num_str);
				exit(INPUT_INVALID);
			}
			tmp_set.insert(tmp_quanID);
		}
		if (str_quantums.size() == str_quantums.max_size()) {
			perror("Error @ Str quantums push back failed. \n");
			exit(MALLOC_FAILED);
		}
		str_quantums.push_back(tmp_set);
	}
	orig_data.close();

	hash_matrix = (uint32_t**) malloc(sizeof(uint32_t*) * NUM_TWO_QUANTUM);
	for (int i = 0; i < NUM_TWO_QUANTUM; i++) {
		hash_matrix[i] = (uint32_t*) malloc(sizeof(uint32_t) * num_hashFunc);
	}
	if (!hash_matrix) {
		perror("Error @ Hash Matrix memalloc failed. \n");
		exit(MALLOC_FAILED);
	}

	minHash_perStr = (uint32_t*) malloc(num_hashFunc * sizeof(uint32_t));
	if (!minHash_perStr) {
		perror("Error @ MinHash Per String memalloc failed. \n");
		exit(MALLOC_FAILED);
	}

	//Compute pseudo permutation Matrix
	//uint32_t hash_value;
	//	for(int i = 0; i < NUM_TWO_QUANTUM; i++){
	//		for(unsigned int j = 0; j < num_hashFunc; j++){
	//			MurmurHash3_x86_32(&i,sizeof(int),seed[j],&hash_value);
	//			hash_matrix[i][j] = hash_value;
	//		}
	//	}

	uint32_t hash_value[4];
	for (int i = 0; i < NUM_TWO_QUANTUM; i++) {
		for (unsigned int j = 0; j < num_hashFunc; j++) {
			MurmurHash3_x64_128(&i, sizeof(int), seed[j], hash_value);
			hash_matrix[i][j] = hash_value[0];
		}
	}

///Time recording Starts
#if defined(__APPLE__)
	struct timeval t1;
	struct timeval t2;
	double time_used;
	gettimeofday(&t1, NULL);

#else
	//t_start = clock();
#endif

	for (unsigned int i = 0; i < num_str; i++) {
		//Initiate SIG as +infinite Matrix (maybe okay to use Memset)
		for (unsigned int j = 0; j < num_hashFunc; j++) {
			minHash_perStr[j] = ULONG_MAX;
		}
		// SIG(i,j) = MIN{SIG(i,j),Hash(quan,j)}
		for (int quantum_in_str : str_quantums.at(i)) {
			for (unsigned int j = 0; j < num_hashFunc; j++) {
				minHash_perStr[j] =
						(minHash_perStr[j] > hash_matrix[quantum_in_str][j]) ?
								hash_matrix[quantum_in_str][j] :
								minHash_perStr[j];
			}
		}
		//Update alpha_minHash
		for (unsigned int j = 0; j < num_betaHash; j++) {
			//Takes in jth alpha_hashs and return an SHA1 value of [j||hash1...hash\alpha] string
			convertAlphaHashsToSHA1(sha1_perStr,
					minHash_perStr + j * num_alphaHash, j, num_alphaHash);
			AlphaHashs newAH = AlphaHashs(sha1_perStr, i);
			//Insert alpha_minHash into alpha_binSet
			std::set<AlphaHashs>::iterator existed = alpha_binSet.find(newAH);
			if (existed != alpha_binSet.end()) {
				if (existed->str_pos == NUM_STRID) {
					perror("Error @ updating AlphaHashs binSet. \n");
					exit(MALLOC_FAILED);
				}
				existed->str_index[existed->str_pos++] = i;
			} else {
				if (alpha_binSet.size() == alpha_binSet.max_size()) {
					perror("Error @ inserting alpha_binSet. \n");
					exit(MALLOC_FAILED);
				}
				alpha_binSet.insert(newAH);
			}
		}
	}

#if defined(__APPLE__)
	gettimeofday(&t2, NULL);
	time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
	//printf("Time elapsed (ms): %f \n", time_used);
#else
	//t_end = clock();
	//t_elapsed = t_end - t_start;
	//printf("Time elapsed (ms): %d \n",t_elapsed);
#endif
///Time Recording Ends

	//Result Output
	//printf("%lu\n",alpha_binSet.size());
	;
	hashtables.open(orig_path.append(".lsh").c_str());
	for (AlphaHashs elem : alpha_binSet) {
		for (int i = 0; i < LEN_SHA1; i++) {
			hashtables << std::hex << static_cast<int>(elem.sha1_value[i])
					<< " ";
		}
		hashtables << std::dec << elem.str_pos << " ";
		for (int i = 0; i < elem.str_pos; i++) {
			hashtables << elem.str_index[i] << " ";
		}
		hashtables << std::endl;
	}
	hashtables.close();

	//free the matrice and arrays
	for (unsigned int i = 0; i < str_quantums.size(); i++) {
		str_quantums[i].clear();
	}
	str_quantums.clear();
	for (unsigned int i = 0; i < NUM_TWO_QUANTUM; i++) {
		free(hash_matrix[i]);
	}
	free(hash_matrix);
	free(seed);
	return 0;
}

int returnQuantumIndex(char former_c, char latter_c) {
	//[a-z] + [0-9] Only
	int index = -1;

	if (former_c >= 'a' && former_c <= 'z') {
		index = (former_c - 'a' + 10); // [0-9] + a...
	} else if (former_c >= '0' && former_c <= '9') {
		index = (former_c - '0');
	} else {
		perror("Error @ former char input is illegal. \n");
		return INPUT_INVALID;
	}
	index *= 36;
	if (former_c >= 'a' && former_c <= 'z') {
		index += (latter_c - 'a' + 10); // [0-9] + a...
	} else if (former_c >= '0' && former_c <= '9') {
		index += (latter_c - '0');
	} else {
		perror("Error @ latter char input is out of boundary. \n");
		return INPUT_INVALID;
	}
	return index;
}

int convertAlphaHashsToSHA1(unsigned char* dest, uint32_t* source,
		unsigned int id_betaHash, size_t num_alphaHash) {
	//TODO Not robust, dest string memory allocation not checked
	size_t len_alphaHashs = num_alphaHash * sizeof(uint32_t);
	if (!dest) {
		perror("Error @ dest pointer invalid. \n");
		return INPUT_INVALID;
	}
	unsigned char* alpha_hashs;
	alpha_hashs = (unsigned char*) malloc(sizeof(int) + len_alphaHashs);
	if (!alpha_hashs) {
		perror("Error @ MinHash unsigned chars memalloc failed. \n");
		return MALLOC_FAILED;
	}
	memcpy(alpha_hashs, (char *) &id_betaHash, sizeof(int));
	memcpy(alpha_hashs + sizeof(int), (char *) source, len_alphaHashs);
	SHA1(alpha_hashs, sizeof(int) + len_alphaHashs, dest);

	/*printf("Conversion %d\n",id_betaHash);
	 for(unsigned int i = 0 ; i < len_alphaHashs + sizeof(int); i++){
	 if(i == sizeof(int)){
	 printf("\n");
	 }
	 printf("%d ",alpha_hashs[i]);
	 }
	 printf("\n");
	 printf("Alpha Hashs: \n");
	 for(unsigned int i = 0; i < num_alphaHash; i++){
	 printf("%lu ",source[i]);
	 }
	 printf("\n");*/

	return EXE_SUCCESS;
}

int sha1Cmp(const unsigned char* pre_sha1, const unsigned char* suf_sha1) {
	int diff_pos;

	for (diff_pos = 0; diff_pos < LEN_SHA1; diff_pos++) {
		if (pre_sha1[diff_pos] != suf_sha1[diff_pos]) {
			break;
		}
	}
	if (diff_pos == LEN_SHA1) {
		return EXE_SUCCESS;
	} else {
		return pre_sha1[diff_pos] - suf_sha1[diff_pos];
	}
}
