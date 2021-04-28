#ifndef TEA_HH
#define TEA_HH


void TEA_encrypt(uint32_t[], uint32_t[]);
void TEA_decrypt(uint32_t[], uint32_t[]);
void printHex(uint32_t[], int);

const uint32_t DELTA = 0x9E3779B9;


#endif  // TEA_HH