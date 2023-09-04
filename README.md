# Hash2603 Readme

Hash2603 is a versatile cryptographic hash function with variable output lengths and rounds. It can be used to generate hash codes for various purposes, including securing passwords and verifying sensitive information.
### Remember, this single code can generate 108 type of hashes
## Usage

To use Hash2603 to generate hash codes, follow these steps:

1. Import the `Hash2603` class from the `hash2603` module.

   ```python
   from hash2603 import Hash2603
   ```

2. Create a `Hash2603` object by providing the input data, which can be a file name, bytes, or text.

   ```python
   hash_obj = Hash2603("HERE WILL BE FILE NAME OR BYTES OR TEXTS")
   ```

3. Define the desired hash length and round. The hash length is specified using the `Bn` notation, where `n` is the desired length in bits (e.g., `B128` for a 128-bit hash). The round is specified using the `URn` notation, where `n` is the desired round (e.g., `UR4` for 4 rounds).

4. Call the corresponding hash function to obtain the hash code.

   ```python
   hash_value = hash_obj.UR4hash128()  # Example: UR4 means 4 rounds and hash128 means 128-bit output
   ```

5. Repeat step 4 with different hash lengths and rounds as needed.

## Hash Lengths and Rounds

Hash2603 supports various hash lengths (`B0`, `B1`, `B2`, `B4`, `B8`, `B16`, `B32`, `B64`, `B128`, `B256`, `B512`, `B1024`) and rounds (`UR1` to `UR10`). Here's a quick reference:

- `B0` to `B128` can be obtained from `UR1` to `UR10`.
- `B256` can be obtained from `UR2` to `UR10`.
- `B512` can be obtained from `UR4` to `UR10`.
- `B1024` can be obtained from `UR9` to `UR10`.

## Example

Below is an example of generating hash codes for different hash lengths and rounds:

```python
# For quick check run test.py 
from hash2603 import Hash2603

hash_obj = Hash2603("HERE WILL BE FILE NAME OR BYTES OR TEXTS")

# Example hash generation for different lengths and rounds
UR1hash0 = hash_obj.UR1hash0()
UR2hash0 = hash_obj.UR2hash0()
# ...

# Print hash values
print("UR1hash0:", UR1hash0)
print("UR2hash0:", UR2hash0)
# ...

# Repeat the process for other hash lengths and rounds
```

## Use Case

Hash2603 is designed for lightweight cryptographic applications, such as hashing small files, text, or securing passwords. For more security-sensitive applications, consider using Hash2600, a more advanced version of this hash function.



Feel free to explore and use Hash2603 for your cryptographic needs! If you encounter any issues or have suggestions for improvement, please don't hesitate to [report them](https://github.com/ZenithSuite/hash2603/issues) on GitHub.
