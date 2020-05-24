#include <iostream>
#include <stdint.h>
#include "ecc.h"
#include <time.h>
#include <fstream>

using namespace std;
ofstream out("output.txt");

// ECC_BYTES = 32
int main() {
	uint8_t p_publicKey[ECC_BYTES + 1];
	uint8_t p_privateKey[ECC_BYTES];
	uint8_t p_hash[ECC_BYTES];
	uint8_t p_signature[ECC_BYTES * 2];
	clock_t start, stop;
	double array[100];
	//clock_t array[100];
	double startTime, endTime;
	
	for (int i = 0; i < 100; i++) {
		//start = clock();
		//startTime = getCPUTime();
		int flag1 = ecc_make_key(p_publicKey, p_privateKey); // Создать пару
		//cout << typeid(p_publicKey).name() << endl;
		//cout << typeid(p_privateKey).name() << endl;

		
		//string message = "80"; // Показания
		// Записать данные в переменную, которая поступит как Хэш сообщение
		//for (int i = 0; i < sizeof(p_hash); i++) {
		//	p_hash[i] = 80;
		//}

		// Создание подписи
		int flag2 = ecdsa_sign(p_privateKey, p_hash, p_signature);
		// Проверка подписи
		int flag3 = ecdsa_verify(p_publicKey, p_hash, p_signature);
		//stop = clock();
		//endTime = getCPUTime();
		//array[i] = stop - start;
		//array[i] = endTime - startTime;
		//out << array[i] << endl;
		//cout << array[i] << " ";
	}
	//cout << stop - start << endl;
	
	//fprintf(stderr, "CPU time used = %lf\n", (endTime - startTime));
	return 0;
}
