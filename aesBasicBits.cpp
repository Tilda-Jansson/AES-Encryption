#include <cstdint>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>


typedef uint8_t byte;
typedef uint32_t word;


/* Rijndael S-box: A fixed precomputed 256-element array used for the SubBytes step
 * This substitution step provides non-linearity in the cipher. Is invertible.
 *
 * The value to substitute the given byte to is calculated as:
 * 1) Take the multiplicative inverse in the finite field GF(2^8)
 * 2) Apply a defined affine transformation over GF(2), can be constructed as a matrix multiplication.
 * 
 * (xy): row x, column y
 * copied from : https://en.wikipedia.org/wiki/Rijndael_S-box
 */
const byte s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Rcon array used in the key expansion process
// The round constant word array
// contains the values given by [x^(i-1),{00},{00},{00}], i starts at 1.
// powers of x under multiplication as denoted in the field GF(2^8)
const word Rcon[11] = {
    0x00000000, // Not used
    0x01000000, // Rcon[1] konstant
    0x02000000, // Rcon[2] x
    0x04000000, // Rcon[3] x^2
    0x08000000, // Rcon[4] x^3
    0x10000000, // Rcon[5] x^4
    0x20000000, // Rcon[6] x^5
    0x40000000, // Rcon[7] x^6
    0x80000000, // Rcon[8] x^7
    0x1b000000, // Rcon[9] x^8 is substituted by x^4+x^3+x+1 due to x^8 modulo m(x)
    0x36000000  // Rcon[10] x^9 is substituted by 0x36 due to x^9 modulo m(x)
};

/* Applies the S-box to each byte of a four-byte input word to produce an output word.
 * Used during the Key Expansion process for generating round keys. 
 */
word SubWord(word w) {
    return (word(s_box[w >> 24]) << 24) | // 1st byte of the word
           (word(s_box[(w >> 16) & 0xff]) << 16) | // mask the 2nd byte of the word
           (word(s_box[(w >> 8) & 0xff]) << 8) | // mask 3rd byte of the word
           (word(s_box[w & 0xff])); // mask 4th byte of the word
}

/* Performs a cyclic permutation on a four-byte word.
 * Used in the Key Expansion process. 
 * MSB is wrapped around to the least significant byte's (LSB) place. 
 * I.e. multiply the polynomial of a(x)={01}x^3 + {00}x^2 + {00}x + {00} with the word represented as a 4-term polynomial.
 */
word RotWord(word w) {
    return word((w << 8) | (w >> 24)); //bitwise OR
}

/* Expands the cipher key into an array of key schedule words.
 * The expanded keys are used in each round of the AES algorithm. 
 */
void KeyExpansion(const byte key[], std::vector<word>& w, int Nk) {
    int Nr = Nk + 6; // Number of rounds
    word temp;
    int i = 0;

    // First 4 words of the expanded key are filled with the cipher key
    while (i < Nk) {
        w[i] = (word(key[4 * i]) << 24) | // combine 4 bytes with bitwise xor into one word
               (word(key[4 * i + 1]) << 16) |
               (word(key[4 * i + 2]) << 8) |
               word(key[4 * i + 3]);
        i++;
    }

    i = Nk; // To fill in the rest of the words of the keys:

    while (i < 4 * (Nr + 1)) {
        temp = w[i - 1];

        if (i % Nk == 0) { // for words in positions that are a multiple of Nk
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk]; // transformation then xor with round constant
        } 
        //else if (Nk > 6 && i % Nk == 4) { //Only for AES-256 with Nk=8
        //    temp = SubWord(temp);
        //}

        w[i] = w[i - Nk] ^ temp; //XOR of the previous word temp and the word Nk=4 positions earlier
        i++;
    }
}


/* Non-linear byte substitution using the S-box.
 * Each byte of the state is independently replaced with its corresponding value in the S-box. */
void SubBytes(byte state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = s_box[state[i][j]];
        }
    }
}

/* Processes the State by cyclically shifting the last three rows of the State by different offsets (bytes). 
 * This step increases diffusion in the cipher. */
void ShiftRows(byte state[4][4]) {
    byte temp;

    // Shift row 1
    temp = state[1][0];
    for (int i = 0; i < 3; ++i) 
        state[1][i] = state[1][i + 1]; // offset = 1
    state[1][3] = temp;

    // Shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift row 3
    temp = state[3][3];
    for (int i = 3; i > 0; --i) 
        state[3][i] = state[3][i - 1]; // move back by 1 pos 
    state[3][0] = temp;
}


// xtime operation: Multiplies a byte by x in GF(2^8)
byte xtime(byte a) {
    // left shift, i.e. multiplication by x which is {02}
    /*
    * XORing with 0x1b modifies the lower bits (x^4, x^3, x, and the constant term)
    * in a way that the result, when seen as a polynomial, is equivalent to having done a modulo operation with m(x).
    * The result remains within the confines of the 8-bit field.
    * 
    * so if the index 7 bit is set we know that the multiplication by x is going to result in a 8-degree polynomial - 
    * but since a byte only is 8 bits, it is enough to xor with 0x1b and not 0x011b since we only consider 8 bits
    * */
    return byte((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)); // left shift, i.e. multiplication by x which is {02}
}

/* Performs multiplication in the Galois Field (2^8).
 * Used in the MixColumns step to mix the data within each column. 
 * 
 * Multiply finite field elements (Bytes): 
 * Corresponds to multiplication of polynomials modulo the irreducable polynomial m(x)= x^8 + x^4 + x^3 + x + 1
 * 
 * repeated multiplication x times a, and intermediate results are added to res when lsb in b is 1.
 */
byte gmul(byte a, byte b) {
    byte res = 0;
    for (int i = 0; i < 8; i++) { //least to most significant bit
        if (b & 1) //lsb of b
            res ^= a; //add to res

        a = xtime(a); // Multiply a by x
        b >>= 1; //next bit in b to the least significant position for the next iteration
    }
    return res;
}


/* Mixes the columns of the state matrix, combining the four bytes in each column.
 * This step provides diffusion in the cipher. 
 * Takes all of the columns of the State and mixes their data (independently of one another) to produce new columns. 
 * 
 * Each column is treated as a 4-term polynomial over GF(2^8) and multiplied modulo (x^4 + 1) with the fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
 * I.e.:
 * 1) Multiply the "column polynomial" b(x) with the fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
 * 2) Take the result modulo (x^4 + 1) to get a 4-byte word
 * 
 * Alt.: The coefficients of the new 4-term polynomial (the 4 bytes of the new column) can be calculated with matrix multiplication,
 * used below:  
 */
void MixColumns(byte state[4][4]) {
    byte temp[4];
    for (int i = 0; i < 4; ++i) {
        temp[0] = state[0][i];
        temp[1] = state[1][i];
        temp[2] = state[2][i];
        temp[3] = state[3][i];

        state[0][i] = gmul(temp[0], 2) ^ gmul(temp[1], 3) ^ gmul(temp[2], 1) ^ gmul(temp[3], 1);
        state[1][i] = gmul(temp[0], 1) ^ gmul(temp[1], 2) ^ gmul(temp[2], 3) ^ gmul(temp[3], 1);
        state[2][i] = gmul(temp[0], 1) ^ gmul(temp[1], 1) ^ gmul(temp[2], 2) ^ gmul(temp[3], 3);
        state[3][i] = gmul(temp[0], 3) ^ gmul(temp[1], 1) ^ gmul(temp[2], 1) ^ gmul(temp[3], 2);
    }
}


/* Each byte of the state is XORed with the round key.
 * This step introduces the key into the state.
 * 
 * Each of the 4 words in the round key are added into the columns of the state
 */
void AddRoundKey(byte state[4][4], const word* roundKey) {
    for (int i = 0; i < 4; ++i) { // for each word in key...
        word k = roundKey[i]; 
        for (int j = 0; j < 4; ++j) { // xor the word of the key with the i:th column
            state[j][i] ^= (k >> (24 - j * 8)) & 0xff; // mask the least significant byte of the key (after shift)
        }
    }
}

// Encrypts a single block of 16 bytes using the key schedule.
void Cipher(byte in[16], byte out[16], const std::vector<word>& keySchedule) {
    byte state[4][4];
    // Load the input block into the state array
    for (int i = 0; i < 16; ++i) {
        state[i % 4][i / 4] = in[i]; // filled in a column-major order
    }

    // Initial AddRoundKey
    AddRoundKey(state, &keySchedule[0]); //original cipher key

    // 9 Rounds, 4 byte-oriented transformations
    for (int round = 1; round < 10; ++round) {
        SubBytes(state); // using a substitution table (S-box)
        ShiftRows(state); // of the State array by different offsets
        MixColumns(state); // mixing the data within each column
        AddRoundKey(state, &keySchedule[round * 4]); // add 128-bit round key to the state
    }

    // Final 10th round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &keySchedule[10 * 4]); //10th round key

    // Copy the state to the output array
    for (int i = 0; i < 16; ++i) {
        out[i] = state[i % 4][i / 4];
    }
}


// Reads the AES key and data blocks from stdin, encrypts them, and writes to stdout.
int main() {
    // AES-128 requires a 16-byte key
    byte key[16];

    // Read the 128-bit key from stdin
    if (fread(key, 1, 16, stdin) != 16) {
        std::cerr << "Error reading key from stdin" << std::endl;
        return 1;
    }

    // Initialize key schedule and perform key expansion
    // keySchedule consists of a one-dimensional array of words - for key size 192, 256 bits -> longer key schedule -> more rounds
    /*
    * KeyExpansion generates 40 words = 10 128-bit round keys. (+ includes cipher key = 44 words)
    * keySchedule: original cipher key (the first 4 words) and 10 more 4-word round keys
    */
    std::vector<word> keySchedule(4 * (10 + 1)); // AES-128 has 10 rounds
    KeyExpansion(key, keySchedule, 4); // Nk = 4 for 128-bit key

    byte block[16], encryptedBlock[16];
    while (true) {
        // Read a block, 16 bytes, of data from stdin
        size_t bytesRead = fread(block, 1, 16, stdin);
        if (bytesRead == 0) {
            break; // No more data to read
        }
        if (bytesRead < 16) { // checks nr of bytes read
            // Pad the last block with zeros if it's not a full block
            memset(block + bytesRead, 0, 16 - bytesRead);
        }

        // Encrypt the block and write to stdout
        Cipher(block, encryptedBlock, keySchedule);
        fwrite(encryptedBlock, 1, 16, stdout);
    }

    return 0;
}



