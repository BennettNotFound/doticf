using System.Security.Cryptography;

namespace doticf;

public static class Crypto
{
    // Default keys from prompt
    public static readonly byte[] ICF_KEY = Convert.FromHexString("09ca5efd30c9aaef3804d0a7e3fa7120");
    public static readonly byte[] ICF_IV = Convert.FromHexString("b155c22c2e7f0491fa7f0fdc217aff90");

    public static byte[] DecryptIcf(byte[] data, byte[] key, byte[] iv)
    {
        int size = data.Length;
        byte[] decrypted = new byte[size];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        using var decryptor = aes.CreateDecryptor();

        for (int i = 0; i < size; i += 4096)
        {
            int fromStart = i;
            int bufsz = Math.Min(4096, size - fromStart);

            // Decrypt the chunk
            // NOTE: TransformBlock works, but we need to be careful with the last block if it's partial?
            // Actually, we established the file size is always a multiple of 64, so it's aligned.
            int bytesDecrypted = decryptor.TransformBlock(data, i, bufsz, decrypted, i);

            // Apply XOR logic to the decrypted chunk
            // Rust:
            // let xor1 = u64::from_le_bytes(decbuf[0..8].try_into()?) ^ (from_start as u64);
            // let xor2 = u64::from_le_bytes(decbuf[8..16].try_into()?) ^ (from_start as u64);
            
            // In C#, we modify 'decrypted' in place at offset 'i'
            
            ulong xor1 = BitConverter.ToUInt64(decrypted, i) ^ (ulong)fromStart;
            ulong xor2 = BitConverter.ToUInt64(decrypted, i + 8) ^ (ulong)fromStart;

            BitConverter.TryWriteBytes(new Span<byte>(decrypted, i, 8), xor1);
            BitConverter.TryWriteBytes(new Span<byte>(decrypted, i + 8, 8), xor2);
        }

        return decrypted;
    }

    public static byte[] EncryptIcf(byte[] data, byte[] key, byte[] iv)
    {
        int size = data.Length;
        byte[] encrypted = new byte[size];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        // Temporary buffer for the chunk to be encrypted (because we need to XOR it first)
        byte[] tempBuf = new byte[4096];

        for (int i = 0; i < size; i += 4096)
        {
            int fromStart = i;
            int bufsz = Math.Min(4096, size - fromStart);

            // Copy data to temp buffer
            Array.Copy(data, i, tempBuf, 0, bufsz);

            // Apply XOR logic
            // Rust:
            // let xor1 = u64::from_le_bytes(buf[0..8].try_into()?) ^ (from_start as u64);
            // let xor2 = u64::from_le_bytes(buf[8..16].try_into()?) ^ (from_start as u64);

            ulong xor1 = BitConverter.ToUInt64(tempBuf, 0) ^ (ulong)fromStart;
            ulong xor2 = BitConverter.ToUInt64(tempBuf, 8) ^ (ulong)fromStart;

            BitConverter.TryWriteBytes(new Span<byte>(tempBuf, 0, 8), xor1);
            BitConverter.TryWriteBytes(new Span<byte>(tempBuf, 8, 8), xor2);

            // Encrypt
            encryptor.TransformBlock(tempBuf, 0, bufsz, encrypted, i);
        }

        return encrypted;
    }
}
