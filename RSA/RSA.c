#define _CRT_SECURE_NO_WARNINGS//VS 宏，抑制使用不安全函数报错的
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

typedef uint8_t byte;
char* plainfile = NULL;
char* nfile = NULL;
char* efile = NULL;
char* dfile = NULL;
char* cipherfile = NULL;
char* signfile = NULL;
char* pfile = NULL;
char* qfile = NULL;

char* plainfiletext = NULL;
uint64_t plainfiletextlength = 0;
char* nfiletext = NULL;
uint64_t nfiletextlength = 0;
char* efiletext = NULL;
uint64_t efiletextlength = 0;
char* dfiletext = NULL;
uint64_t dfiletextlength = 0;
char* cipherfiletext = NULL;
uint64_t cipherfiletextlength = 0;
char* signfiletext = NULL;
uint64_t signfiletextlength = 0;
char* pfiletext = NULL;
uint64_t pfiletextlength = 0;
char* qfiletext = NULL;
uint64_t qfiletextlength = 0;

void print_usage() {
	/*
		参数输入错误提示，并退程序
	*/
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-n nfile 指定存放整数n 的文件的位置和名称\n-e efile 在数据加密时，指定存放整数e 的文件的位置和名称\n-d dfile 在数字签名时，指定存放整数d 的文件的位置和名称\n-c cipherfile 指定密文文件的位置和名称\n-s signfile 指定签名文件的位置和名称\n-P pfile  在数据加密时，指定存放大素数p 的文件的位置和名称\n-Q qfile  在数据加密时，指定存放大素数q 的文件的位置和名称\n");
	exit(-1);
}

bool readfile2memory(const char* filename, byte** memory, uint64_t* memorylength) {
	/*
	读取文件到内存
	*/
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*memory = malloc(size+1);
	memset(*memory, 0, size + 1);

	fread(*memory, size, 1, fp);
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	printf("readfile2memory debug info:%s",*memory);
	
	printf("\n");

	return true;
}

bool writestr2file(const char* file, const char* str) {
	FILE* fp = NULL;
	fp = fopen(file, "w");
	if (fp == NULL) {
		printf("打开文件%s失败！\n", file);
		return false;
	}
	fwrite(str, strlen(str), 1, fp);
	printf("写入文件%s成功！\n", file);
	fclose(fp);
	return true;
}

void print_help(char* bufname, byte* buf, uint8_t bytes) {
	/*
	打印调试信息
	*/
	printf("%s信息:\n", bufname);
	/*for (int i = 0; i < bytes; i++) {
		printf("%c", buf[i]);
	}*/
	//printf("\n");
	for (int i = 0; i < bytes; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n\n");
	/*for (int i = 0; i < bytes; i++) {
		for (int j = 7; j >= 0; j--) {
			if (buf[i] & 1 << j) {
				printf("1");
			}
			else {
				printf("0");
			}
		}
		printf("\n");
	}
	printf("\n\n");*/
}

void RecoverPrimeFactors(BIGNUM* n, BIGNUM* e, BIGNUM* d, BIGNUM** p, BIGNUM** q) {
	//从n,e,d中恢复p和q，
	//最简单的思路就是从10^10方开始便利找到素数到sqar(n)，找到后用n整除得到另一个数，判断是否是素数，
	//然后计算phi(n)，再计算phi(n)-1，再计算e^(phi(n)-1)mod n看看结果于d是否相等，下面是一种优化的算法
	//摘自下述文档
	https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf Appendix C
	
		  
	//1.Let k= de–1. If kis odd, then go to Step 4
step1:;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* k = BN_new();
	BN_mul(k, d, e, ctx);
	BN_sub(k, k, BN_value_one());
	BN_CTX_free(ctx);
	if (BN_is_odd(k)) {
		goto step4;
	}
	
	//2.Write k as k= (2^t)r, where r is the largest odd integer dividing k, and t>=1.
step2:;
	BIGNUM* t = BN_new();
	BN_set_word(t, 0);
	BIGNUM* r = BN_new();
	BN_set_word(r, 0);
	BIGNUM* BN_value_two = BN_new();
	BN_set_word(BN_value_two, 2);
	while (true) {
		ctx = BN_CTX_new();
		BIGNUM* tmp = BN_new();
		BN_mod(tmp, k, BN_value_two, ctx);
		if (BN_is_zero(tmp)) {
			BN_add_word(t, 1);
		}
		else {
			BN_copy(r, k);
			break;
		}
		BN_div_word(k, 2);
		BN_CTX_free(ctx);
	}
	char* buf = BN_bn2hex(r);
	buf = BN_bn2hex(t);
	//3.For i = 1 to 100 do:
step3:;
	//a.Generate a random integer gin the range[0, n-1].
step3a:;
	BIGNUM* g = BN_new();
	BIGNUM* range = BN_new();
	BN_copy(range, n);
	BN_sub_word(range, 1);
	buf = BN_bn2hex(range);
	BN_rand_range(g, range);
	buf = BN_bn2hex(g);
	//b.Let y= grmod n.
step3b:;
	BIGNUM* y = BN_new();
	ctx = BN_CTX_new();
	BN_MONT_CTX* mctx = BN_MONT_CTX_new();
	BN_mod_exp_recp(y, g, r, n, ctx);
	buf = BN_bn2hex(y);
	BN_CTX_free(ctx);
	BN_MONT_CTX_free(mctx);
	//c.If y= 1 or y= n–1, then go to Step g.
step3c:;
	if (BN_is_one(y))
		goto step3g;
	BIGNUM* res = BN_new();
	BN_sub(res, n, y);
	if (BN_is_one(res)) {
		BN_free(res);
		goto step3g;
	}
	BN_free(res);
	//d.For j= 1 to t–1 do:
step3d:;
	//i.Let x= y2mod n.
step3di:;
	BIGNUM* x = BN_new();
	ctx = BN_CTX_new();
	BN_mod_exp(x, y, BN_value_two, n, ctx);
	buf = BN_bn2hex(x);
	BN_CTX_free(ctx);
	//ii.If x= 1, go to Step 5.
step3dii:;
	if (BN_is_one(x))
		goto step5;
	//iii.If x= n–1, go to Stepg.
step3diii:;
	res = BN_new();
	BN_copy(res, n);
	BN_sub_word(res, 1);
	if (BN_cmp(x, res) == 0) {
		BN_free(res);
		goto step3g;
	}
	BN_free(res);
		
	//iv.Let y= x
step3div:;
	BN_copy(y, x);
	//e. Let x= y2mod n.
step3e:;
	ctx = BN_CTX_new();
	BN_mod_exp(x, y, BN_value_two, n, ctx);
	buf = BN_bn2hex(x);
	BN_CTX_free(ctx);
	//f.If x= 1, go to Step 5
step3f:;
	if (BN_is_one(x))
		goto step5;
	//g.Continue
step3g:;
	goto step3;
	//4.Output “prime factors not found, ”and exit without further processing.
step4:;
	printf("prime factors not found");
	exit(-1);
	//5.Let p= GCD(y–1, n) and let q= n/p.
step5:;
	ctx = BN_CTX_new();
	BIGNUM* y1 = BN_new();
	BN_copy(y1, y);
	BN_sub_word(y1, 1);
	BN_gcd(*p, y1, n, ctx);
	buf = BN_bn2hex(*p);
	BN_CTX_free(ctx);
	ctx = BN_CTX_new();
	BIGNUM* rem = BN_new();
	BN_div(*q, rem, n, *p, ctx);
	buf = BN_bn2hex(*q);
	BN_CTX_free(ctx);
	//6.Output (p, q) as the prime factors.
step6:;
	return;
}

BIGNUM* egcd(BIGNUM* phin, BIGNUM* e, BIGNUM* x, BIGNUM* y) {
	//拓展欧几里得
	if (BN_is_zero(e)) {
		BN_one(x);
		BN_zero(y);
		BIGNUM* ret = BN_new();
		BN_zero(ret);
		return ret;
	}
	else {
		BIGNUM* mod = BN_new();
		BN_CTX* ctx = BN_CTX_new();
		BN_mod(mod, phin, e, ctx);
		BN_CTX_free(ctx);
		BIGNUM* r = egcd(e, mod, x, y);
		BIGNUM* bak = BN_new();
		BIGNUM* tmp = BN_new();
		BN_copy(bak, y);
		ctx = BN_CTX_new();
		BN_div(tmp, NULL, phin, e, ctx);
		BN_CTX_free(ctx);
		ctx = BN_CTX_new();
		BN_mul(tmp, tmp, y, ctx);
		BN_CTX_free(ctx);
		BN_sub(y, x, tmp);
		BN_copy(x, bak);
		return y;

	}
}

int main(int argc, char** argv) {

	printf("argc:%d\n", argc);
	for (int i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
		-p plainfile 指定明文文件的位置和名称
		-n nfile 指定存放整数n 的文件的位置和名称
		-e efile 在数据加密时，指定存放整数e 的文件的位置和名称
		-d dfile 在数字签名时，指定存放整数d 的文件的位置和名称
		-c cipherfile 指定密文文件的位置和名称

		-s signfile 指定签名文件的位置和名称
		-P pfile  在数据加密时，指定存放大素数p 的文件的位置和名称
		-Q qfile  在数据加密时，指定存放大素数q 的文件的位置和名称
	*/

	for (int i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
			case 'p':
				plainfile = argv[i + 1];
				break;
			case 'n':
				nfile = argv[i + 1];
				break;
			case 'e':
				efile = argv[i + 1];
				break;
			case 'd':
				dfile = argv[i + 1];
				break;
			case 'c':
				cipherfile = argv[i + 1];
				break;
			//extra
			case 'P':
				pfile = argv[i + 1];
				break;
			case 'Q':
				qfile = argv[i + 1];
				break;
			case 's':
				signfile = argv[i + 1];
				break;
			default:
				print_usage();
		}
	}

	if (plainfile == NULL || nfile == NULL || efile == NULL || dfile == NULL || cipherfile == NULL || qfile == NULL || pfile == NULL || signfile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("明文文件的位置和名称:%s\n", plainfile);
	printf("存放整数n 的文件的位置和名称:%s\n", nfile);
	printf("存放整数e 的文件的位置和名称:%s\n", efile);
	printf("存放整数d 的文件的位置和名称:%s\n", dfile);
	printf("密文文件的位置和名称:%s\n", cipherfile);
	printf("签名文件的位置和名称:%s\n", signfile);
	printf("存放整数q 的文件的位置和名称:%s\n", qfile);
	printf("存放整数p 的文件的位置和名称:%s\n", pfile);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plainfiletext, &plainfiletextlength);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");
	printf("读取存放整数n 的文件...\n");
	read_result = readfile2memory(nfile, &nfiletext, &nfiletextlength);
	if (read_result == false) {
		printf("读取存放整数n 的文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取存放整数n 的文件成功！\n");
	printf("读取存放整数e 的文件...\n");
	read_result = readfile2memory(efile, &efiletext, &efiletextlength);
	if (read_result == false) {
		printf("读取存放整数e 的文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取存放整数e 的文件成功！\n");
	printf("读取存放整数d 的文件...\n");
	read_result = readfile2memory(dfile, &dfiletext, &dfiletextlength);
	if (read_result == false) {
		printf("读取存放整数d 的文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取存放整数d 的文件成功！\n");
	printf("文件读取完毕！\n");

	BIGNUM* m = BN_new();
	BIGNUM* n = BN_new();
	BIGNUM* d = BN_new();
	BIGNUM* e = BN_new();
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BN_hex2bn(&m, plainfiletext);
	BN_hex2bn(&n, nfiletext);
	BN_hex2bn(&d, dfiletext);
	BN_hex2bn(&e, efiletext);

	RecoverPrimeFactors(n, e, d, &p, &q);
	char* buffer = 0;
	buffer = BN_bn2hex(p);
	printf("获取到 P:%s\n", buffer);
	writestr2file(pfile, buffer);
	buffer = BN_bn2hex(q);
	printf("获取到 Q:%s\n", buffer);
	writestr2file(qfile, buffer);

	BIGNUM* cipher = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_mod_exp_recp(cipher, m, e, n, ctx);
	BN_CTX_free(ctx);
	buffer = BN_bn2hex(cipher);
	printf("获取到 cipher:%s\n", buffer);
	writestr2file(cipherfile, buffer);

	BIGNUM* sign = BN_new();
	ctx = BN_CTX_new();
	BN_mod_exp_recp(sign, m, d, n, ctx);
	BN_CTX_free(ctx);
	buffer = BN_bn2hex(sign);
	printf("获取到 sign:%s\n", buffer);
	writestr2file(signfile, buffer);

	printf("正在生成新公私钥对...\n");
	char rnd_seed[] = "种子：不能用于实际环境";
	RAND_seed(rnd_seed, sizeof(rnd_seed));
	
	BIGNUM* newp = BN_new();
	BIGNUM* newq = BN_new();
	BN_generate_prime_ex(newp, 129, 0, NULL, NULL, NULL);
	BN_generate_prime_ex(newq, 129, 0, NULL, NULL, NULL);
	buffer = BN_bn2hex(newp);
	printf("生成的新的p为：%s\n", buffer);
	buffer = BN_bn2hex(newq);
	printf("生成的新的q为：%s\n", buffer);
	BIGNUM* newp_1 = BN_new();
	//BN_copy(newp_1, p);
	BN_copy(newp_1, newp);
	BN_sub_word(newp_1, 1);
	BIGNUM* newq_1 = BN_new();
	//BN_copy(newq_1, q);
	BN_copy(newq_1, newq);
	BN_sub_word(newq_1, 1);
	BIGNUM* phi = BN_new();
	ctx = BN_CTX_new();
	BN_mul(phi, newp_1, newq_1, ctx);
	BN_CTX_free(ctx);
	BIGNUM* phi_1 = BN_new();
	BN_copy(phi_1, phi);
	BN_sub_word(phi_1, 1);
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	BIGNUM* newd = egcd(phi, e, x, y);
	if (BN_is_negative(newd)) {
		BN_add(newd, newd, phi);
	}
	/*ctx = BN_CTX_new();
	BN_gcd(newd, e, n, ctx);
	BN_CTX_free(ctx);*/
	buffer = BN_bn2hex(newd);
	printf("生成的新的d为：%s\n", buffer);
	


	return 0;
}

//#include <stdio.h>
//#include <stdint.h>
//#include <stdlib.h>
//#include <stdbool.h>
//#include <string.h>
//#include <assert.h>
//
//#define and &&
//#define or ||
//#define xor ^
//#define max(a,b) ((a)>(b)?(a):(b))
//#define _BIGGER(a,b)((a)>(b)?true:false)
//
//#define bg 1 //bigger
//#define eq 0 //==
//#define sl -1 //smaller
//
//typedef struct bignum bignum;
//struct bignum{
//    bool ispositive;
//	uint8_t* num;
//	uint64_t len;
//};
//
//bignum* bn_add(bignum* a, bignum* b);
//bignum* bn_multiply(bignum* a, bignum* b);
//
//bignum* bn_new() {
//	bignum* bn = malloc(sizeof(bignum));
//    memset(bn, 0, sizeof(bignum));
//    assert(bn != NULL);
//    bn->len = 0;
//    bn->ispositive = true;
//    bn->num = 0;
//	return bn;
//}
//void* bn_free(bignum*bn) {
//    if (bn == NULL)return;
//    free(bn->num);
//    free(bn);
//    return;
//}
//bignum* bn_copy(bignum* bn) {
//    bignum* c = malloc(sizeof(bignum));
//    c->ispositive = bn->ispositive;
//    c->len = bn->len;
//    c->num = malloc(bn->len);
//    memcpy(c->num, bn->num, bn->len);
//    return c;
//}
//
//void bn_times0x100(bignum* bn) {
//    assert(bn != NULL and bn->num != NULL);
//    if (bn->len == 1 and bn->num[0] == 0)
//        return;
//    uint8_t* tmp = malloc(bn->len);
//    memcpy(tmp, bn->num, bn->len);
//    free(bn->num);
//    bn->len += 1;
//    bn->num = malloc(bn->len);
//    memcpy(bn->num + 1, tmp, bn->len - 1);
//    bn->num[0] = 0;
//    return;
//}
//
//void bn_times0x100s(bignum* bn,uint64_t factor) {
//    assert(bn != NULL and bn->num != NULL);
//    if (bn->len == 1 and bn->num[0] == 0)
//        return;
//    if (factor == 0)
//        return;
//    uint8_t* tmp = malloc(bn->len);
//    memcpy(tmp, bn->num, bn->len);
//    free(bn->num);
//    bn->len += factor;
//    bn->num = malloc(bn->len);
//    memset(bn->num, 0, bn->len);
//    memcpy(bn->num + factor, tmp, bn->len - factor);
//    return;
//}
//
//bignum* bn_timesUN(bignum* bn, uint8_t UN) {
//    if (UN == 0) {
//        bignum* s = bn_new();
//        s->ispositive = true;
//        s->len = 1;
//        s->num = malloc(1);
//        s->num[0] = 0;
//        return s;
//    }
//    bignum* s = bn_new();
//    s->ispositive = true;
//    s->len = 1;
//    s->num = malloc(1);
//    s->num[0] = UN;
//    bignum* res = bn_multiply(bn, s);
//    bn_free(s);
//    return res;
//}
//
//bignum* bn_addUN(bignum* bn, uint8_t UN) {
//    bignum* s = bn_new();
//    s->ispositive = true;
//    s->len = 1;
//    s->num = malloc(1);
//    s->num[0] = UN;
//    bignum* res = bn_add(bn, s);
//    bn_free(s);
//    return res;
//}
//
//void bn_set(bignum* lvalue, bignum* rvalue) {
//    assert(lvalue != NULL and rvalue != NULL);
//    if (lvalue->len == rvalue->len) {
//        lvalue->ispositive = rvalue->ispositive;
//        memcpy(lvalue->num, rvalue->num, lvalue->len);
//    }
//    else {
//        if (lvalue->num != NULL) {
//            free(lvalue->num);
//        }
//        lvalue->len = rvalue->len;
//        lvalue->ispositive = rvalue->ispositive;
//        lvalue->num = malloc(lvalue->len);
//        memcpy(lvalue->num, rvalue->num, lvalue->len);
//    }
//    return;
//}
//
//bool hexstrtobin(uint8_t** bin, uint64_t* binsz, const uint8_t* hexconst, uint64_t hexsize) {
//    
//    uint8_t* hex = malloc(hexsize);
//    memcpy(hex, hexconst, hexsize);
//
//    if (hexsize == 0 || hex == NULL || binsz == NULL || bin == NULL) {
//        return false;
//    }
//
//    for (uint64_t i = 0; i < hexsize; i++) {//first pass check charactor and convert to lower
//        if (hex[i] > 'f' || hex[i] < '0' || (hex[i] > '9' && hex[i] < 'A') || (hex[i] > 'F' && hex[i] < 'a')) {
//            //invalid char
//            return false;
//        }
//        if (hex[i] >= 'A' && hex[i] <= 'F') {
//            //to lower
//            hex[i] += 0x20;
//        }
//    }
//
//    *binsz = hexsize % 2 == 0 ? hexsize / 2 : (hexsize + 1) / 2;
//    *bin = malloc(*binsz);
//    memset(*bin, 0, *binsz);
//
//    if (hexsize % 2 == 0) {
//        for (int64_t i = hexsize - 1; i >= 0; i--) {
//            if (hex[i] < 'a') {
//                //number
//                (*bin)[(hexsize % 2 == 0 ? i : i + 1) / 2] += (hex[i] - 0x30) * (i % 2 == 0 ? 0x10 : 0x1);
//            }
//            else {
//                //charactor
//                (*bin)[(hexsize % 2 == 0 ? i : i + 1) / 2] += (hex[i] - 0x57) * (i % 2 == 0 ? 0x10 : 0x1);
//            }
//
//        }
//    }
//    else {
//        for (int64_t i = hexsize - 1; i >= 0; i--) {
//            if (hex[i] < 'a') {
//                //number
//                (*bin)[(hexsize % 2 == 0 ? i : i + 1) / 2] += (hex[i] - 0x30) * (i % 2 == 0 ? 0x1 : 0x10);
//            }
//            else {
//                //charactor
//                (*bin)[(hexsize % 2 == 0 ? i : i + 1) / 2] += (hex[i] - 0x57) * (i % 2 == 0 ? 0x1 : 0x10);
//            }
//
//        }
//    }
//    
//
//}
//
//bool bintohexstr(uint8_t** hex, uint64_t* hexsz, uint8_t* bin, uint64_t binsz) {
//    uint8_t charcode[] = "0123456789abcdef";
//    *hexsz = binsz * 2;
//    *hex = malloc(*hexsz);
//    memset(*hex, 0, *hexsz);
//    for (uint64_t i = 0; i < binsz; i++) {
//        (*hex)[2 * i] = charcode[bin[i] / 0x10];
//        (*hex)[2 * i + 1] = charcode[bin[i] % 0x10];
//    }
//    return true;
//}
//
//bool reverthex(uint8_t* hex, uint64_t hexsz) {
//    if (hex[0] == '0' and (hex[1] == 'x' or hex[1] == 'X')) {
//        hex += 2;
//        hexsz -= 2;
//    }
//    uint8_t* tmp = malloc(hexsz);
//    memcpy(tmp, hex, hexsz);
//   
//    for (int i = 0; i < hexsz; i += 2) {
//        if (i + 1 == hexsz) {
//            hex[hexsz - 1 - i] = tmp[i];
//        }
//        else {
//            hex[hexsz - 1 - i] = tmp[i + 1];
//            hex[hexsz - 1 - i - 1] = tmp[i];
//        }
//            
//    }
//    free(tmp);
//    
//}
//
//bool revertbin(uint8_t* bin, uint64_t binsz) {
//    uint8_t* tmp = malloc(binsz);
//    memcpy(tmp, bin, binsz);
//    for (uint64_t i = 0; i < binsz; i++) {
//        bin[i] = tmp[binsz - 1 - i];
//    }
//    free(tmp);
//}
//
//bool bn_set_from_hex_str(bignum* bn, const uint8_t* hexstr, bool ispositive) {
//	assert(bn != NULL);
//	if (hexstr[0] == '0' and (hexstr[1] == 'x' or hexstr[1] == 'X')) {
//		hexstr += 2;
//	}
//	uint64_t charlen = strlen(hexstr);
//	if (charlen % 2 != 0)
//		charlen += 1;
//	bn->len = charlen / 2;
//	bn->num = malloc(charlen / 2);
//    bn->ispositive = ispositive;
//    uint8_t* bin;
//    uint64_t binsz;
//    hexstrtobin(&bin, &binsz, hexstr, strlen(hexstr));
//    assert(binsz == bn->len);
//    for (uint64_t i = 0; i < binsz; i++) {
//        bn->num[i] = bin[binsz - 1 - i];
//    }
//
//    for (uint64_t i = binsz - 1; i >= 0; i--) {
//        if (bn->num[i] == 0) {
//            bn->len--;
//        }
//        else {
//            break;
//        }
//    }
//    return true;
//}
//
//bool bn_set_from_hex_bin(bignum* bn, const uint8_t* hexbin, const uint64_t hexbinlen, bool ispositive) {
//    assert(bn != NULL);
//    bn->len = hexbinlen;
//    bn->num = malloc(hexbinlen);
//    bn->ispositive = ispositive;
//    memcpy(bn->num, hexbin, hexbinlen);
//    revertbin(bn->num, hexbinlen);
//    for (uint64_t i = hexbinlen - 1; i >= 0; i--) {
//        if (bn->num[i] == 0) {
//            bn->len--;
//        }
//        else {
//            break;
//        }
//    }
//    return true;
//}
//
//int8_t unsigned_bigger(bignum* left, bignum* right) {
//    if (left->len > right->len) {
//        return bg;
//    }
//    else if(left->len < right->len){
//        return sl;
//    }
//    else {//==
//        if (memcmp(left->num, right->num, left->len) == 0) {
//            return eq; 
//        }
//        for (uint64_t i = left->len - 1; i >= 0; i--) {
//            if (left->num[i] != right->num[i]) {
//                if (_BIGGER(left->num[i], right->num[i])) {
//                    return bg;
//                }
//                else {
//                    return sl;
//                }
//            }
//        }
//    }
//}
//
//int8_t bigger(bignum* left, bignum* right) {
//    if (left->ispositive and !right->ispositive) {
//        return bg;
//    }
//    else if (!left->ispositive and right->ispositive) {
//        return sl;
//    }
//    else if (!left->ispositive and !right->ispositive) {
//        return -1 * unsigned_bigger(left, right);
//    }
//    else if (left->ispositive and right->ispositive) {
//        return unsigned_bigger(left, right);
//    }
//}
//
//bignum* bn_minus(bignum* left, bignum* right) {
//    if (left->ispositive and !right->ispositive) {
//        bignum* tmp = bn_copy(right);
//        tmp->ispositive = true;
//        bignum* res = bn_add(left, tmp);
//        free(tmp);
//        return res;
//    }
//    else if (!left->ispositive and right->ispositive) {
//        bignum* tmp = bn_copy(right);
//        tmp->ispositive = false;
//        bignum* res = bn_add(left, tmp);
//        free(tmp);
//        return res;
//    }
//    else if (!left->ispositive and !right->ispositive) {
//        bignum* tmpa = bn_copy(left);
//        bignum* tmpb = bn_copy(right);
//        tmpa->ispositive = true;
//        tmpb->ispositive = true;
//        bignum* res = bn_minus(tmpb, tmpa);
//        free(tmpa);
//        free(tmpb);
//        return res;
//    }
//    
//    bignum* c = bn_new();
//    int8_t res = bigger(left, right);
//    switch (res) {
//    case sl:
//        c->ispositive = false;
//        bignum* tmp = left;
//        left = right;
//        right = tmp;
//        //break; let it go to bg case
//    case bg:
//        if (res == bg) {
//            c->ispositive = true;
//        }
//        uint8_t* buffer = malloc(left->len);
//        memset(buffer, 0, left->len);
//        uint64_t bufferlen = 0;
//        uint8_t bl = 0;
//        for(uint64_t i = 0; i < right->len; i++) {
//            if (left->num[i] < right->num[i]) {
//                buffer[i] = left->num[i] + 0x100 - right->num[i] - bl;
//                bl = 1;
//            }
//            else if (left->num[i] >= right->num[i]) {
//                buffer[i] = left->num[i] - right->num[i] - bl;
//                bl = 0;
//            }
//        }
//        for (uint64_t i = right->len; i < left->len; i++) {
//            buffer[i] = left->num[i] - bl;
//            bl = 0;
//        }
//        bufferlen = left->len;
//        for (uint64_t i = left->len - 1; i >= 0; i--) {
//            if (buffer[i] == 0) {
//                bufferlen--;
//            }
//            else {
//                break;
//            }
//        }
//        c->len = bufferlen;
//        c->num = malloc(bufferlen);
//        memcpy(c->num, buffer, bufferlen);
//        break;
//    case eq:
//        c->len = 1;
//        c->num = malloc(1);
//        c->num[0] = 0;
//        c->ispositive = true;
//        break;
//    default:
//        //should not be here
//        assert(false);
//        break;
//    }
//    return c;
//}
//
//bignum* bn_add(bignum* a, bignum* b) {
//    if (a->ispositive and !b->ispositive) {
//        bignum* tmp = bn_copy(b);
//        tmp->ispositive = true;
//        bignum* res = bn_minus(a, tmp);
//        free(tmp);
//        return res;
//    }
//    else if (!a->ispositive and b->ispositive) {
//        bignum* tmp = bn_copy(a);
//        tmp->ispositive = true;
//        bignum* res = bn_minus(b, tmp);
//        free(tmp);
//        return res;
//    }
//
//    uint8_t* buffer = malloc(max(a->len, b->len) + 1);
//    uint64_t buflen = 0;
//    memset(buffer, 0, max(a->len, b->len) + 1);
//    
//    int16_t sum = 0;
//    uint64_t round = max(a->len, b->len);
//    for (uint64_t i = 0; i < round; i++) {
//        sum = (i >= a->len ? 0 : a->num[i]) + (i >= b->len ? 0 : b->num[i]) + sum;
//        buffer[buflen] = sum % 0x100;
//        buflen++;
//        sum = sum / 0x100;
//    }
//    if (sum != 0) {
//        buffer[buflen] = sum;
//        buflen++;
//    }
//    bignum* c = bn_new();
//    c->len = buflen;
//    c->num = malloc(buflen);
//    memcpy(c->num, buffer, buflen);
//    c->ispositive = a->ispositive;
//    return c;
//}
//
//void rightshiftbytes(uint8_t* buffer, uint64_t bufferlen,uint64_t bytes) {
//    for (int64_t i = bufferlen - 1; i >= 0; i--) {//feature not bug
//        buffer[i + bytes] = buffer[i];
//    }
//    for (uint64_t i = 0; i < bytes; i++) {
//        buffer[i] = 0;
//    }
//}
//
//void add_buffer(uint8_t* dst, uint8_t* src, uint64_t bufferlen) {
//    uint16_t res = 0;
//    for (uint64_t i = 0; i < bufferlen; i++) {
//        res = dst[i] + src[i] + res / 0x100;
//        dst[i] = res % 0x100;
//    }
//}
//
//bignum* bn_multiply(bignum* a, bignum* b) {
//    uint64_t buffertotallen = a->len + b->len + 1;
//    uint8_t* buffer = malloc(buffertotallen);
//    memset(buffer, 0, buffertotallen);
//    uint8_t* roundbuffer = malloc(buffertotallen);
//    memset(roundbuffer, 0, buffertotallen);
//    uint64_t bufferlen = 0;
//
//    for (uint64_t bi = 0; bi < b->len; bi++) {
//        uint16_t res = 0;
//        for (uint64_t ai = 0; ai < a->len; ai++) {
//            res = b->num[bi] * a->num[ai] + res / 0x100;
//            roundbuffer[ai] = res % 0x100;
//        }
//        roundbuffer[a->len] = res / 0x100;
//        rightshiftbytes(roundbuffer, a->len + 1 , bi);
//        add_buffer(buffer, roundbuffer, buffertotallen);
//        memset(roundbuffer, 0, buffertotallen);
//    }
//    bufferlen = buffertotallen;
//    for (int64_t i = buffertotallen - 1; i >= 0; i--) {
//        if (buffer[i] == 0) {
//            bufferlen--;
//        }
//        else {
//            break;
//        }
//    }
//
//    bignum* c = bn_new();
//    c->ispositive = (a->ispositive == b->ispositive ? true : false);
//    c->len = bufferlen;
//    c->num = malloc(bufferlen);
//    memcpy(c->num, buffer, bufferlen);
//    return c;
//}
//
//bignum* bn_divide(bignum* dividend, bignum* divisor) {//dividend / divisor 
//    assert(dividend != NULL and divisor != NULL and dividend->len != 0 and divisor->len != 0);
//    if (divisor->len == 1 and divisor->num[0] == 0) {
//        assert("divide by 0" == NULL);
//    }
//    int8_t res = unsigned_bigger(dividend, divisor);
//    switch (res) {
//    case bg:;
//        bignum* tmpdividend = bn_new();
//        bignum* tmpdivisor = bn_new();
//        bn_set(tmpdividend, dividend);
//        uint8_t* buffer = malloc(dividend->len - divisor->len + 1);
//        uint64_t bufferlen = dividend->len - divisor->len + 1;
//        memset(buffer, 0, dividend->len - divisor->len + 1);
//        for (int64_t i = dividend->len - divisor->len; i >= 0; i--) {
//            bn_set(tmpdivisor, divisor);
//            bn_times0x100s(tmpdivisor, i);
//            uint8_t res;
//            for (res = 1; res < 0x100; res++) {
//                bignum* tr = bn_timesUN(tmpdivisor, res);
//                if (unsigned_bigger(tmpdividend, tr) == sl) {
//                    free(tr);
//                    break;
//                }
//                free(tr);
//            }
//            buffer[i] = res - 1;
//            bignum* tr = bn_timesUN(tmpdivisor, res - 1);
//            bignum* newdividend = bn_minus(tmpdividend, tr);
//            bn_set(tmpdividend, newdividend);
//            bn_free(tr);
//            bn_free(newdividend);
//        }
//        for (int64_t i = bufferlen - 1; i >= 0; i--) {
//            if (buffer[i] == 0) {
//                bufferlen--;
//            }
//            else {
//                break;
//            }
//        }
//        bignum* d = bn_new();
//        d->ispositive = dividend->ispositive == divisor->ispositive ? true: false;
//        d->len = bufferlen;
//        d->num = malloc(bufferlen);
//        memcpy(d->num, buffer, bufferlen);
//        bn_free(tmpdividend);
//        bn_free(tmpdivisor);
//        free(buffer);
//        return d;
//        break;
//    case sl:;
//        bignum* c = bn_new();
//        c->len = 1;
//        c->num = malloc(1);
//        c->num[0] = 0;
//        c->ispositive = true;
//        return c;
//        break;
//    case eq:;
//        bignum* cc = bn_new();
//        cc->len = 1;
//        cc->num = malloc(1);
//        cc->num[0] = 1;
//        cc->ispositive = (dividend->ispositive == divisor->ispositive ? true : false);
//        return cc;
//        break;
//    default:
//        //should not be here
//        break;
//    }
//
//}
//
//bignum* bn_mod(bignum* dividend, bignum* divisor) {
//    bignum* c = bn_divide(dividend, divisor);
//    bignum* m = bn_multiply(c, divisor);
//    bignum* r = bn_minus(dividend, m);
//    bn_free(c);
//    bn_free(m);
//    return r;
//}
//
//bignum* bn_power(bignum* base, bignum* power) {
//    assert(base != NULL and power != NULL and power->ispositive == true);
//    if (power->len == 1 and power->num[0] == 0) {
//        bignum* r = bn_new();
//        r->ispositive = true;
//        r->len = 1;
//        r->num = malloc(1);
//        r->num[0] = 1;
//        return r;
//    }
//    else if (power->len == 1 and power->num[0] == 1) {
//        bignum* r = bn_copy(base);
//        return r;
//    }
//    bignum* sum = bn_copy(base);
//    bignum* one = bn_new();
//    one->ispositive = true;
//    one->len = 1;
//    one->num = malloc(1);
//    one->num[0] = 1;
//    bignum* iter = bn_minus(power, one);
//    while (iter->len != 1 || iter->num[0] != 0) {
//        bignum* m = bn_multiply(sum, base);
//        bn_set(sum, m);
//        bn_free(m);
//        bignum* newiter = bn_minus(iter, one);
//        bn_set(iter, newiter);
//        bn_free(newiter);
//    }
//    bn_free(iter);
//    bn_free(one);
//    return sum;
//}
//
//int main() {
//
//    bignum* p= bn_new();
//    bignum* q = bn_new();
//    bn_set_from_hex_str(p, "63727970746F677261706879", true);
//    bn_set_from_hex_str(q, "10001", true);
//    bignum* c = bn_power(p, q);
//    int a = 0;
//    
//    /*uint8_t hex[] = "abcde";
//    uint64_t hexsz = 5;
//    reverthex(hex, hexsz);*/
//    /*for (int i = 0; i < hexsz; i++) {
//        printf("%c", hex[i]);
//    }*/
//
//	return 0;
//}