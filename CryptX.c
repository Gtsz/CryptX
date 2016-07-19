// CryptX 是一種基於 Logistic 迭代的混沌對稱加密算法，基於 C 語言實作
// 特性：
// 加密偶次即解密
// 多次加密毋須順序解密
// 作者： Gtsz
// License: GPL v3.0

#include <stdio.h>

typedef unsigned char byte;

void codec(char*, char*, char*);
long int str_size(char*);
void usage();

int main(int argc, char *argv[])
{
	if (argc == 4){
		printf("CryptX-Alpha-1.0\n");
		printf("input file: %s\n", argv[1]);
		printf("output file: %s\n", argv[2]);
		codec(argv[3], argv[1], argv[2]);
	} else {
		usage(1);
	}
    return 0;
}

void codec(char* key, char* infile_name, char* outfile_name)
{
	FILE *outfile, *infile;
	int t_calc, count, i, j;
	float key_temp;
	long int file_length;
	const long int BUFLEN = 8192; // 緩衝區大小， 必須爲 4 的倍數（浮點數長度）
	int float_length = sizeof(float); // 預先取得 float 佔用位元組，避免之後頻繁呼叫 sizeof 函數
	
	printf("buffer size: %d Byte(s)\n", BUFLEN);
	
	if (!(infile = fopen(infile_name, "rb")) || fseek(infile, 0, SEEK_END)){ // 開啓檔案，然後將指針移至文件末，同時作例外處理
		usage();
	}
	
	long int seed_length = str_size(key) + 1;
	float seed[seed_length];
	float key_mtx[seed_length][BUFLEN / float_length + 1]; // 緩衝區內原始密鑰陣列，大小爲緩衝區長度與密碼字元數之乘積
	float key_temp_arr[seed_length];
	byte buffer[BUFLEN];
	outfile = fopen(outfile_name, "wb");
	file_length = ftell(infile);
	rewind(infile);

	printf("file size: %d Byte(s)\n", file_length);
	printf("key length: %d\n", seed_length - 1);
	printf("Processing started...\n");
	
	// 納入密鑰源
	seed[0] = 0.2f + (float)(file_length%919)/1000000; // 檔案長度作一因子，取一質數以 mod，避免過大，降冪
	for (i = 1; *key; i++){
		seed[i] = 0.2f + (float)(*key++)/1000000; // 密碼字元各作因子，降冪
	}
	
	// 初始化密鑰陣列
	t_calc = 23; // 跳過開始的可預測部分
	for (i = 0; i < seed_length; i++){
		key_temp_arr[i] = seed[i];
		t_calc++; // 移位，密碼必須順序正確
        for (j = 0; j < t_calc; j++){
			key_temp = key_temp_arr[i];
            key_temp_arr[i] = 4.0f * key_temp * (1.0f - key_temp); // 預計算密鑰
        }
    }

	// 讀取檔案並加密／解密
	while ((count = fread(buffer, 1, BUFLEN, infile)) != 0){
		t_calc = count / float_length + 1;
		for (i = 0; i < seed_length; i++){
			key_mtx[i][0] = key_temp_arr[i];
			for (j = 1; j < t_calc; j++){
				key_mtx[i][j] = 4.0f * key_mtx[i][j-1] * (1.0f - key_mtx[i][j-1]); // 計算密鑰
			}
			for (j = 0; j < count; j++){
				buffer[j] ^= *((byte*)&key_mtx[i][0] + j); // 將一個密鑰浮點數轉換爲四個位元組與檔案內容作異或運算
			}
			key_temp_arr[i] = key_mtx[i][t_calc-1];
		}
        fwrite(buffer, 1, count, outfile);
    }
	
    fclose(infile);
    fclose(outfile);
	printf("Processing finished\n");
}

void usage()
{
    printf("Usage: CryptX <input_file> <output_file> <key>\n");
	printf("Process odd number of times to encrypt, even number of times to decrypt\n");
	printf("\nversion: alpha-1.0\n");
	printf("by Gtsz(email:chuyt@live.hk)\n");
	exit(1);
}

long int str_size(char* str){
	long int count;
	for (count = 0; *str; count++){
		*str++;
	}
	return count;
}
