#include "sqlite3.h"
#include<Windows.h>
#include<iostream>
#include<vector>
#include<string>
#include <cassert>
#include <openssl\evp.h>
#include <openssl\ssl.h>
#include<openssl\aes.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
/*
static const char* szSqlite_path = "C:\\Users\\dell\\AppData\\Roaming\\secoresdk\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db";
static const char* szKey = "5cbfe6e6-21aa-40df-8b1e-895f086fc497";
*/
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char aes_key[] = { 0x63, 0x66, 0x36, 0x36, 0x66, 0x62, 0x35, 0x38, 0x66, 0x35, 0x63, 0x61, 0x33, 0x34, 0x38, 0x35 };

using namespace std;

std::string aes_128_ecb_decrypt(const std::string& ciphertext, const char* key)
{
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (const unsigned char*)key, NULL);
	unsigned char* result = new unsigned char[ciphertext.length() + 64]; // 弄个足够大的空间
	int len1 = 0;
	ret = EVP_DecryptUpdate(ctx, result, &len1, (const unsigned char*)ciphertext.data(), ciphertext.length());
	int len2 = 0;
	ret = EVP_DecryptFinal_ex(ctx, result + len1, &len2);
	ret = EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	std::string res((char*)result, len1 + len2);
	delete[] result;
	return res;
}

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_decode(std::string const& encoded_string, std::string base64_chars) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}


class sqlresult{
public:
	sqlresult()
	{

	}

	sqlresult(string domain, string account, string encode_password, string decode_password)
	{
		this->m_domain = domain;
		this->m_account = account;
		this->m_encode_password = encode_password;
		this->m_decode_password = decode_password;
	}
	
	~sqlresult()
	{
		
	}
public:
	string m_domain;
	string m_account;
	string m_encode_password;
	string m_decode_password;
};


// 回调函数
int _callback(void* data, int argc, char** argv, char** szColName){
	for (int i = 0; i < argc; i++){
		cout << szColName[i] << endl;
	}
	return 0;
}

class SqliteDecrypt{
public:

	SqliteDecrypt()
	{
	
	}

	SqliteDecrypt(string szSqlite_path, string szKey){
		this->szdb_path = szSqlite_path;
		this->szpass_key = szKey;
	}

	~SqliteDecrypt()
	{
		sqlite3_close(this->sqlite3_obj);
		
	}

private:
	int _init_database(){
		if (!(sqlite3_open(this->szdb_path.c_str(), &sqlite3_obj) == SQLITE_OK)){
			cout << "sqlite3_open failed!" << endl;
			return -1;
		}

		if (!(sqlite3_key(this->sqlite3_obj, this->szpass_key.c_str(), this->szpass_key.size()) == SQLITE_OK))
		{
			cout << "sqlite3_key failed!" << endl;
			sqlite3_close(this->sqlite3_obj);
			return -1;
		}
		
		return 0;
	}
	
	int _select_tbaccount(){

		if (sqlite3_exec(sqlite3_obj, (const char*)"select domain, username, password from tb_account;", _callback, NULL, NULL) == SQLITE_OK){
			cout << "select * from tb_account" << endl;
			return -1;
		}

		//遍历进行解密操作
		for (int i; i < v_sqlresult.size(); i++){
			v_sqlresult[i].m_decode_password = _decode_func(v_sqlresult[i].m_encode_password);
		}
		
		return 0;
		
	}

	int _show_decrypt_records(){
		for (int i; i < v_sqlresult.size(); i++){
			cout << "domain: " << v_sqlresult[i].m_account << "account: " << v_sqlresult[i].m_account << "password: " << v_sqlresult[i].m_decode_password << endl;
 		}
		return 0;
	}

	string _decode_func(string encode_password){
		// aes128 ecb解码
		// base64解码
		string wow_decode_password = aes_128_ecb_decrypt(base64_decode(encode_password, base64_chars), aes_key);
		return wow_decode_password;
	}

	// machine_guid还没写
	string _get_machine_guid(){
		string machineguid;
		return machineguid;
	}

private:
	string szdb_path;
	string szpass_key;
	string machine_guid;
	sqlite3* sqlite3_obj = NULL;
	vector<sqlresult> v_sqlresult;
	int sqlresult_size = 0;
};

int main(int argc, char* argv[]){
	if (argc == 2)
	{
		SqliteDecrypt(argv[0], argv[1]);
	}

	/*
	std::string decrypt = aes_128_ecb_decrypt(base64_decode("S5/J5teUYGTpWLxtIVB6EM7xAv1HKq9utI90kdMhCmE=", base64_chars), aes_key);
	std::cout << "AES解密:" + decrypt << std::endl;*/
	return 0;
}