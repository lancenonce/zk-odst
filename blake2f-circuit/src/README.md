Function Compress
   Input:
      h                      Persistent state vector
      chunk                  128-byte (16 double word) chunk of message to compress
      t: Number, 0..2128     Count of bytes that have been fed into the Compression
      IsLastBlock: Boolean   Indicates if this is the final round of compression
   Output:
      h                      Updated persistent state vector

   Setup local work vector V
   V0..7 ← h0..7   First eight items are copied from persistent state vector h
   V8..15 ← IV0..7 Remaining eight items are initialized from the IV

   circuit layout // Todo complete

        |         | s1  |  s2 |  s3 |  s4 |  s5 |
        | V0..7   |  1  |  0  |  0  |  0  |  0  |
        | V8..15  |  0  |  1  |  0  |  0  |  0  |
        | V12     |  0  |  0  |  1  |  0  |  0  |
        | V13     |  0  |  0  |  0  |  1  |  0  |
        | V14     |  0  |  0  |  0  |  0  |  1  |


   Mix the 128-bit counter t into V12:V13
   V12 ← V12 xor Lo(t)    Lo 64-bits of UInt128 t
   V13 ← V13 xor Hi(t)    Hi 64-bits of UInt128 t
  
   If this is the last block then invert all the bits in V14
   if IsLastBlock then
      V14 ← V14 xor 0xFFFFFFFFFFFFFFFF
   
   Treat each 128-byte message chunk as sixteen 8-byte (64-bit) words m
   m0..15 ← chunk  
   // is decomposition check really required? or can be done by just splitting of words into chunks?
   // Todo implement decomposition of message into chunks see 0xparc tutorials and 
   // and decomposition gadget here: https://zcash.github.io/halo2/design/gadgets/decomposition.html


   // Todo mixing circuit

        |         | s1  |  s2 |  s3 |  s4 |  s5 |
        | V0..7   |  1  |  0  |  0  |  0  |  0  |
        | V8..15  |  0  |  1  |  0  |  0  |  0  |
        | V12     |  0  |  0  |  1  |  0  |  0  |
        | V13     |  0  |  0  |  0  |  1  |  0  |
        | V14     |  0  |  0  |  0  |  0  |  1  |

   Twelve rounds of cryptographic message mixing
   for i from 0 to 11 do
      Select message mixing schedule for this round.
       BLAKE2b uses 12 rounds, while SIGMA has only 10 entries.
      S0..15 ← SIGMA[i mod 10]   Rounds 10 and 11 use SIGMA[0] and SIGMA[1] respectively

      Mix(V0, V4, V8,  V12, m[S0], m[S1])
      Mix(V1, V5, V9,  V13, m[S2], m[S3])
      Mix(V2, V6, V10, V14, m[S4], m[S5])
      Mix(V3, V7, V11, V15, m[S6], m[S7])

      Mix(V0, V5, V10, V15, m[S8],  m[S9])
      Mix(V1, V6, V11, V12, m[S10], m[S11])
      Mix(V2, V7, V8,  V13, m[S12], m[S13])
      Mix(V3, V4, V9,  V14, m[S14], m[S15])
   end for

   Mix the upper and lower halves of V into ongoing state vector h
   h0..7 ← h0..7 xor V0..7
   h0..7 ← h0..7 xor V8..15

   Result ← h
End Function Compress


Mix(V0, V4, V8,  V12, m[S0], m[S1])

(V0, V4, V8,  V12, m[S0], m[S1]) -> Va, Vb, Vc, Vd , x: message chunks, y : message chunks

Function Mix
   Inputs:
        Va, Vb, Vc, Vd       four 8-byte word entries from the work vector V
        x, y                two 8-byte word entries from padded message m
   Output:
        Va, Vb, Vc, Vd       the modified versions of Va, Vb, Vc, Vd

   Va ← Va + Vb + x          with input
   Vd ← (Vd xor Va) rotateright 32

   Vc ← Vc + Vd              no input
   Vb ← (Vb xor Vc) rotateright 24

   Va ← Va + Vb + y          with input
   Vd ← (Vd xor Va) rotateright 16

   Vc ← Vc + Vd              no input
   Vb ← (Vb xor Vc) rotateright 63

   Result ← Va, Vb, Vc, Vd
End Function Mix


// Todo lookup table or a universal spread table for xor?

A spread table can be defined as a table that maps a 16-bit input value to an output value with its bits interleaved with zero bits. 
This is often used in bit manipulation, parallel computing, or graphics processing to perform operations efficiently. 
In this context, the spread table serves as a lookup table to efficiently interleave the bits of the input with zero bits.

To create a spread table, you need to perform the following steps:

Initialize an empty table with a size of 65536 (2^16) elements, as there are 2^16 possible combinations of 16-bit input values.
Iterate through all possible 16-bit input values (0 to 65535).
For each input value, calculate the output value by interleaving its bits with zero bits.
Store the calculated output value in the corresponding position in the table.
Here's an example of how you can create a spread table in Python:

python
Copy code
def spread_table():
    table = [0] * 65536

    for i in range(65536):
        output = 0
        for j in range(16):
            output |= (i >> j & 1) << (2 * j)
        table[i] = output

    return table

spread_lookup = spread_table()

In this example, the spread_table function initializes an empty table,
iterates through all possible 16-bit input values, calculates the output values
by interleaving their bits with zero bits, and stores them in the table.

The spread table can also be used for range checks by examining the output value. 
If the output value is within a certain range, it implies that the input value is also 
within the corresponding range. This makes it unnecessary to have a separate table for range checks.





