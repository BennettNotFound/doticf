using System.Text;
using System.IO.Hashing;

namespace doticf;

public static class Parser
{
    public static void FixupIcf(byte[] data)
    {
        using var ms = new MemoryStream(data);
        using var reader = new BinaryReader(ms);

        uint reportedIcfCrc = reader.ReadUInt32();
        uint reportedSize = reader.ReadUInt32();
        uint actualSize = (uint)data.Length;

        if (actualSize != reportedSize)
        {
            Console.WriteLine($"[WARN] Reported size {reportedSize} bytes does not match actual size {actualSize} bytes, automatically fixing");
            BitConverter.TryWriteBytes(new Span<byte>(data, 4, 4), actualSize);
        }

        ulong padding = reader.ReadUInt64();
        if (padding != 0)
        {
            throw new Exception("Padding error. Expected 8 NULL bytes.");
        }

        ulong entryCount = reader.ReadUInt64();
        ulong expectedSize = 0x40 * (entryCount + 1);

        if (actualSize != expectedSize)
        {
             Console.WriteLine($"[WARN] Expected size {expectedSize} ({entryCount} entries) does not match actual size {actualSize}, automatically fixing");
             ulong actualEntryCount = (ulong)(actualSize / 0x40) - 1;
             BitConverter.TryWriteBytes(new Span<byte>(data, 16, 8), actualEntryCount);
        }

        // Skip app_id (4), platform_id (3), platform_generation (1) -> 8 bytes
        ms.Seek(8, SeekOrigin.Current);

        uint reportedContainerCrc = reader.ReadUInt32();
        uint checksum = 0;

        // Calculate container checksum
        // chunks_exact(0x40).skip(1)
        for (int i = 0x40; i < data.Length; i += 0x40)
        {
            var container = new Span<byte>(data, i, 0x40);
            if (container[0] == 2 && container[1] == 1)
            {
                checksum ^= Crc32ToUInt32(container);
            }
        }

        if (reportedContainerCrc != checksum)
        {
            Console.WriteLine($"[WARN] Reported container CRC32 ({reportedContainerCrc:X2}) does not match actual checksum ({checksum:X2}), automatically fixing");
            BitConverter.TryWriteBytes(new Span<byte>(data, 32, 4), checksum);
        }

        // Checksum of data[4..]
        uint icfChecksum = Crc32ToUInt32(new ReadOnlySpan<byte>(data, 4, data.Length - 4));
        if (icfChecksum != reportedIcfCrc)
        {
             Console.WriteLine($"[WARN] Reported CRC32 ({reportedIcfCrc:X2}) does not match actual checksum ({icfChecksum:X2}), automatically fixing");
             BitConverter.TryWriteBytes(new Span<byte>(data, 0, 4), icfChecksum);
        }
    }

    private static uint Crc32ToUInt32(ReadOnlySpan<byte> data)
    {
        byte[] hashBytes = Crc32.Hash(data);
        return BitConverter.ToUInt32(hashBytes);
    }

    public static List<IcfData> ParseIcf(byte[] decrypted)
    {
        using var ms = new MemoryStream(decrypted);
        using var reader = new BinaryReader(ms);

        uint checksum = Crc32ToUInt32(new ReadOnlySpan<byte>(decrypted, 4, decrypted.Length - 4));
        uint reportedCrc = reader.ReadUInt32();

        if (reportedCrc != checksum)
        {
            throw new Exception($"Reported CRC32 ({reportedCrc:X2}) does not match actual checksum ({checksum:X2})");
        }

        uint reportedSize = reader.ReadUInt32();
        uint actualSize = (uint)decrypted.Length;
        if (actualSize != reportedSize)
        {
             throw new Exception($"Reported size {reportedSize} does not match actual size {actualSize}");
        }

        ulong padding = reader.ReadUInt64();
        if (padding != 0) throw new Exception("Padding error. Expected 8 NULL bytes.");

        ulong entryCount = reader.ReadUInt64();
        ulong expectedSize = 0x40 * (entryCount + 1);

        if (actualSize != (uint)expectedSize)
        {
             throw new Exception($"Expected size {expectedSize} ({entryCount} entries) does not match actual size {actualSize}");
        }

        string appId = Encoding.UTF8.GetString(reader.ReadBytes(4));
        string platformId = Encoding.UTF8.GetString(reader.ReadBytes(3));
        byte platformGeneration = reader.ReadByte();

        uint reportedContainerCrc = reader.ReadUInt32();
        uint calculatedContainerChecksum = 0;

        for (int i = 0x40; i < decrypted.Length; i += 0x40)
        {
            var container = new Span<byte>(decrypted, i, 0x40);
            if (container[0] == 2 && container[1] == 1)
            {
                calculatedContainerChecksum ^= Crc32ToUInt32(container);
            }
        }

        if (reportedContainerCrc != calculatedContainerChecksum)
        {
            throw new Exception($"Reported container CRC32 ({reportedContainerCrc:X2}) does not match actual checksum ({calculatedContainerChecksum:X2})");
        }

        // Padding check: 24 null bytes? Wait, Rust says 28 bytes?
        // Rust: `if rd.read_bytes(28)?.iter().any(|b| *b != 0)`
        // Wait, let's check Rust `parse_icf` again.
        // `rd.read_bytes(4)?` (app_id) + `rd.read_bytes(3)?` (platform_id) + `rd.read_u8()?` (gen) + `rd.read_u32()?` (crc) = 12 bytes read.
        // `rd.read_bytes(28)?` -> total 40 bytes.
        // 4 (crc) + 4 (size) + 8 (pad) + 8 (count) = 24 bytes read initially.
        // 24 + 12 = 36 bytes.
        // 36 + 28 = 64 bytes (0x40). Correct.
        byte[] padCheck = reader.ReadBytes(28);
        if (padCheck.Any(b => b != 0)) throw new Exception("Padding error. Expected 28 NULL bytes.");

        var entries = new List<IcfData>((int)entryCount);

        for (ulong i = 0; i < entryCount; i++)
        {
            long startPos = ms.Position;
            uint sig = reader.ReadUInt32();

            if (sig != 0x0102 && sig != 0x0201)
            {
                throw new Exception($"Container does not start with signature (0x0102 or 0x0201), byte {startPos:X}");
            }

            bool isPrerelease = (sig == 0x0201);
            uint containerType = reader.ReadUInt32();

            byte[] innerPad = reader.ReadBytes(24);
            if (innerPad.Any(b => b != 0)) throw new Exception("Padding error. Expected 24 NULL bytes.");

            // Total read so far in this block: 4 + 4 + 24 = 32 bytes. 32 bytes remaining.

            if (containerType == 0x0000 || containerType == 0x0001)
            {
                var version = DecodeIcfVersion(reader);
                var datetime = DecodeIcfDatetime(reader);
                var reqSysVer = DecodeIcfVersion(reader);

                byte[] tailPad = reader.ReadBytes(16);
                if (tailPad.Any(b => b != 0)) throw new Exception("Padding error. Expected 16 NULL bytes.");

                if (containerType == 0x0000)
                {
                    entries.Add(new IcfSystemData
                    {
                        Id = platformId,
                        Version = version,
                        DateTime = datetime,
                        RequiredSystemVersion = reqSysVer,
                        IsPrereleaseValue = isPrerelease
                    });
                }
                else
                {
                    entries.Add(new IcfAppData
                    {
                        Id = appId,
                        Version = version,
                        DateTime = datetime,
                        RequiredSystemVersion = reqSysVer,
                        IsPrereleaseValue = isPrerelease
                    });
                }
            }
            else if (containerType == 0x0002)
            {
                string optionId = Encoding.UTF8.GetString(reader.ReadBytes(4));
                var datetime = DecodeIcfDatetime(reader);
                var reqSysVer = DecodeIcfVersion(reader); // Not used in IcfOptionData?
                // Wait, Rust: `let required_system_version = decode_icf_version(&mut rd)?;` but `IcfOptionData` struct has it?
                // Rust `IcfOptionData` has `required_system_version` but `parse_icf` reads it.
                
                byte[] tailPad = reader.ReadBytes(16);
                if (tailPad.Any(b => b != 0)) throw new Exception("Padding error. Expected 16 NULL bytes.");

                entries.Add(new IcfOptionData
                {
                    AppId = appId,
                    OptionId = optionId,
                    DateTime = datetime,
                    RequiredSystemVersion = reqSysVer, // Saved it
                    IsPrereleaseValue = isPrerelease
                });
            }
            else
            {
                // Patch
                byte sequenceNumber = (byte)(containerType >> 8);

                if ((containerType & 1) == 0 || sequenceNumber == 0)
                {
                    Console.WriteLine($"Unknown ICF container type {containerType:X} at byte {startPos:X}, skipping");
                    // Skip remaining 32 bytes (we read 32 bytes header)
                    // Wait, we read 32 bytes header. 32 bytes remaining.
                    // But if we fail here, we need to skip 32 bytes.
                    reader.ReadBytes(32);
                    continue;
                }

                var targetVersion = DecodeIcfVersion(reader);
                var targetDatetime = DecodeIcfDatetime(reader);
                var targetReqSysVer = DecodeIcfVersion(reader);

                var sourceVersion = DecodeIcfVersion(reader);
                var sourceDatetime = DecodeIcfDatetime(reader);
                var sourceReqSysVer = DecodeIcfVersion(reader);

                entries.Add(new IcfPatchData
                {
                    Id = appId,
                    SequenceNumber = sequenceNumber,
                    SourceVersion = sourceVersion,
                    SourceDateTime = sourceDatetime,
                    SourceRequiredSystemVersion = sourceReqSysVer,
                    TargetVersion = targetVersion,
                    TargetDateTime = targetDatetime,
                    TargetRequiredSystemVersion = targetReqSysVer,
                    IsPrereleaseValue = isPrerelease
                });
            }
        }

        return entries;
    }

    public static List<IcfData> DecodeIcf(byte[] data)
    {
        byte[] decrypted = Crypto.DecryptIcf(data, Crypto.ICF_KEY, Crypto.ICF_IV);
        return ParseIcf(decrypted);
    }

    public static byte[] SerializeIcf(List<IcfData> data)
    {
        int entryCount = data.Count;
        int icfLength = 0x40 * (entryCount + 1);
        byte[] icf = new byte[icfLength];
        
        using var ms = new MemoryStream(icf);
        using var writer = new BinaryWriter(ms);

        // Header placeholder
        writer.Write(new byte[0x40]);

        string? platformId = null;
        string? appId = null;

        foreach (var container in data)
        {
            if (container.IsPrerelease)
                writer.Write(new byte[] { 0x01, 0x02, 0x00, 0x00 });
            else
                writer.Write(new byte[] { 0x02, 0x01, 0x00, 0x00 });

            if (container is IcfSystemData sys)
            {
                platformId = sys.Id;
                writer.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            }
            else if (container is IcfAppData app)
            {
                appId = app.Id;
                writer.Write(new byte[] { 0x01, 0x00, 0x00, 0x00 });
            }
            else if (container is IcfOptionData opt)
            {
                writer.Write(new byte[] { 0x02, 0x00, 0x00, 0x00 });
            }
            else if (container is IcfPatchData patch)
            {
                writer.Write(new byte[] { 0x01, patch.SequenceNumber, 0x00, 0x00 });
            }

            writer.Write(new byte[24]); // Padding

            if (container is IcfOptionData o)
            {
                writer.Write(Encoding.UTF8.GetBytes(o.OptionId));
                SerializeDatetime(writer, o.DateTime);
                writer.Write(new byte[20]);
                continue;
            }

            Version ver = new Version();
            DateTime dt = DateTime.MinValue;
            Version reqSys = new Version();

            if (container is IcfSystemData s) { ver = s.Version; dt = s.DateTime; reqSys = s.RequiredSystemVersion; }
            else if (container is IcfAppData a) { ver = a.Version; dt = a.DateTime; reqSys = a.RequiredSystemVersion; }
            else if (container is IcfPatchData p) { ver = p.TargetVersion; dt = p.TargetDateTime; reqSys = p.TargetRequiredSystemVersion; }

            SerializeVersion(writer, ver);
            SerializeDatetime(writer, dt);
            SerializeVersion(writer, reqSys);

            if (container is IcfPatchData pp)
            {
                SerializeVersion(writer, pp.SourceVersion);
                SerializeDatetime(writer, pp.SourceDateTime);
                SerializeVersion(writer, pp.SourceRequiredSystemVersion);
            }
            else
            {
                writer.Write(new byte[16]);
            }
        }

        if (platformId == null) throw new Exception("Missing entry of type System in provided ICF data");
        if (platformId.Length != 3) throw new Exception($"Incorrect platform ID length: expected 3, got {platformId.Length}");
        
        if (appId == null) throw new Exception("Missing entry of type App in provided ICF data");
        if (appId.Length != 4) throw new Exception($"Incorrect app ID length: expected 4, got {appId.Length}");

        uint containersChecksum = 0;
        for (int i = 0x40; i < icfLength; i += 0x40)
        {
            var chunk = new Span<byte>(icf, i, 0x40);
            if (chunk[0] == 2 && chunk[1] == 1)
            {
                containersChecksum ^= Crc32ToUInt32(chunk);
            }
        }

        // Fill header
        // Offset 4: Size (u32)
        BitConverter.TryWriteBytes(new Span<byte>(icf, 4, 4), (uint)icfLength);
        // Offset 16: Entry Count (u64)
        BitConverter.TryWriteBytes(new Span<byte>(icf, 16, 8), (ulong)entryCount);
        // Offset 24: AppID
        Encoding.UTF8.GetBytes(appId).CopyTo(new Span<byte>(icf, 24, 4));
        // Offset 28: PlatformID
        Encoding.UTF8.GetBytes(platformId).CopyTo(new Span<byte>(icf, 28, 3));
        // Offset 32: Container Checksum
        BitConverter.TryWriteBytes(new Span<byte>(icf, 32, 4), containersChecksum);

        // Header Checksum (CRC32 of icf[4..])
        uint icfCrc = Crc32ToUInt32(new ReadOnlySpan<byte>(icf, 4, icfLength - 4));
        BitConverter.TryWriteBytes(new Span<byte>(icf, 0, 4), icfCrc);

        return icf;
    }

    private static DateTime DecodeIcfDatetime(BinaryReader reader)
    {
        short year = reader.ReadInt16();
        byte month = reader.ReadByte();
        byte day = reader.ReadByte();
        byte hour = reader.ReadByte();
        byte minute = reader.ReadByte();
        byte second = reader.ReadByte();
        byte unk = reader.ReadByte(); // Padding or milli? Rust ignores it.

        return new DateTime(year, month, day, hour, minute, second);
    }

    private static Version DecodeIcfVersion(BinaryReader reader)
    {
        byte build = reader.ReadByte();
        byte minor = reader.ReadByte();
        ushort major = reader.ReadUInt16();
        return new Version { Major = major, Minor = minor, Build = build };
    }

    private static void SerializeDatetime(BinaryWriter writer, DateTime dt)
    {
        writer.Write((ushort)dt.Year);
        writer.Write((byte)dt.Month);
        writer.Write((byte)dt.Day);
        writer.Write((byte)dt.Hour);
        writer.Write((byte)dt.Minute);
        writer.Write((byte)dt.Second);
        writer.Write((byte)0x00);
    }

    private static void SerializeVersion(BinaryWriter writer, Version v)
    {
        writer.Write(v.Build);
        writer.Write(v.Minor);
        writer.Write(v.Major);
    }
}
