# AES-128 encryption in ECB mode

Both `aesBasicBits.cpp` and `faster.cpp` files encrypt data using AES-128 in ECB mode. The main difference between the implementations is that `aesBasicBits.cpp` performs multiplication of the finite field elements (bytes) in the Galois Field (2^8), which is used in the MixColumns step to mix the data within each column. The `faster.cpp` implementation uses precomputed gmul arrays to speed up the calculations. 

Also note that `aesBasicBits` includes comments with thorough documentation and explanation for each step and the calculations made.

## Input
Standard input consists of a key to use, followed by one or more blocks to encrypt using that key. The 128-bit key is specified as the first 16 bytes of the input file. Each block consists of exactly 16 bytes.

* See sample input in the `aes_sample.in` file, where the key written in hexadecimal is F4C020A0A1F604FD343FAC6A7E6AE0F9, and the only block to encrypt is F295B9318B994434D93D98A4E449AFD8.

## Output
Standard output contains, for each block, the encryption of that block, in the same format as the input.

* The output for the sample input above, written in hexadecimal, is 52E418CBB1BE4949308B381691B109FE, see the `aes_sample.ans` file. 

## Run
For example, to run the code after compilation, you can use the command `./aes < aes_sample.in > out.ans`.

## Procedure Overview:
The AES-128 encryption process follows these key steps, as outlined in the [Advanced Encryption Standard procedure](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard):

- Key Expansion
- Initial Round Key - bitwise xor

Repeat steps 3-6 nine times for 128-bit keys (eleven times for 192-bit keys and thirteen times for 256-bit keys):
- Substitute Bytes - lookup table
- Shift Rows
- Mix Columns
- Add Round Key

Final Round:
- Substitute Bytes
- Shift Rows
- Add Round Key


