// @author  Christopher Kareem Schmitt
// @version 2.15.2020
// @licence MIT


#include <iostream>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "TEA.hh"


/**
 * Applies the TEA algorithm in 32 rounds to produce ciphertext.  Note that
 * this function will modify the plaintext buffer in-place
 *
 * @param {uint32_t[]} plaintext - the plaintext buffer to encrypt (2x32bit)
 * @param {uint32_t[]} key - the key to use while encypting the plaintext (4x32bit)
 */
void TEA_encrypt(uint32_t plaintext[], uint32_t key[]) {
  uint32_t left = plaintext[0];
  uint32_t right = plaintext[1];
  uint32_t sum = 0x00;

  for (int i = 0; i < 32; i += 1) {
    sum += DELTA;
    left += ((right << 4) + key[0]) ^ ((right >> 5) + key[1]) ^ (right + sum);
    right += ((left << 4) + key[2]) ^ ((left >> 5) + key[3]) ^ (left + sum);
  }

  plaintext[0] = left;
  plaintext[1] = right;
}


/**
 * Applies the TEA encryption algorithm in reverse to decipher ciphertext.  Note
 * that this function modifies the ciphertext buffer in place
 *
 * @param {uint32_t[]} ciphertext - the ciphertext buffer to decrypt (2x32bit)
 * @param {uint32_t[]} key - the key to use while decrypting the ciphertext (4x32bit)
 */
void TEA_decrypt(uint32_t ciphertext[], uint32_t key[]) {
  uint32_t left = ciphertext[0];
  uint32_t right = ciphertext[1];
  uint32_t sum = 0xC6EF3720;

  for (int i = 0; i < 32; i += 1) {
    right -= ((left << 4) + key[2]) ^ ((left >> 5) + key[3]) ^ (left + sum);
    left -= ((right << 4) + key[0]) ^ ((right >> 5) + key[3]) ^ (right + sum);
    sum -= DELTA;
  }

  ciphertext[0] = left;
  ciphertext[1] = right;
}


/**
 * Prints a buffer as a hex number to stdout
 *
 * @param {uint32_t*} array - the buffer to be printed
 * @param {int} size - the size of the buffer to be printed
 */
void printHex(uint32_t array[], int size) {
  printf("0x");
  for (int i = 0; i < size; i += 1) {
    printf("%08X", array[i]);
  }
  printf("\n");
}


/**
 * Usage:
 * TEA.exe <mode> <text> <key>
 *
 * Example (Encrypting):
 * ```
 *  TEA.exe --encrypt 1256D151E53793F3 A56BABCDF000FFFFFFFFFFFFABCDEF01
 * ```
 *
 * Example (Decrypting):
 * ```
 *  TEA.exe --decrypt CD97D6B8B4426743 A56BABCDF000FFFFFFFFFFFFABCDEF01
 * ```
 *
 * NOTE: do NOT use "0x" when inputing hex values.
 *
 * PROBLEM 3: In CBC mode, each block (64bits) of the plaintext is
 * encryped with the standard TEA algorithm with one alteration;
 * before being fed through TEA with the key, the plaintext block
 * is XORed with the previous ciphertext block (except in the case)
 * of the first block, where a unique IV is used).  Decryption would
 * folows a similar process, decrypting one block at a time, and XORing
 * with the previous blocks result (or the IV). 
 */
int main(int argc, char** argv) {
  if (argc != 4) {
    std::cout << "Incorect number of arguments" << std::endl;
    return -1;
  }

  if (!strcmp(argv[1], "--encrypt")) {
    uint32_t text[2];
    uint32_t key[4];

    sscanf(argv[2], "%8x%8x", &text[0], &text[1]);
    sscanf(argv[3], "%8x%8x%8x%8x", &key[0], &key[1], &key[2], &key[3]);

    TEA_encrypt(text, key);
    printHex(text, 2);

    return 0;
  }

  if (!strcmp(argv[1], "--decrypt")) {
    uint32_t text[2];
    uint32_t key[4];

    sscanf(argv[2], "%8x%8x", &text[0], &text[1]);
    sscanf(argv[3], "%8x%8x%8x%8x", &key[0], &key[1], &key[2], &key[3]);

    TEA_decrypt(text, key);
    printHex(text, 2);

    return 0;
  }

  std::cout << "Incorrect flags" << std::endl;
  return -1;
}