using System.Text.Json;
using System.Text.Json.Serialization;

namespace doticf;

// --- 核心：NativeAOT 源码生成器上下文 ---
// 这个上下文会告诉编译器：在编译时就生成这些类的序列化逻辑，别等运行后再去用反射找。



// --- 以下是你原本的模型代码，保持逻辑不变，仅微调兼容性 ---

[JsonConverter(typeof(VersionConverter))]
public struct Version : IComparable<Version>, IEquatable<Version>
{
    public ushort Major { get; set; }
    public byte Minor { get; set; }
    public byte Build { get; set; }

    public override string ToString() => $"{Major}.{Minor:D2}.{Build:D2}";

    public int CompareTo(Version other)
    {
        int majorComparison = Major.CompareTo(other.Major);
        if (majorComparison != 0) return majorComparison;
        int minorComparison = Minor.CompareTo(other.Minor);
        if (minorComparison != 0) return minorComparison;
        return Build.CompareTo(other.Build);
    }

    public bool Equals(Version other) => Major == other.Major && Minor == other.Minor && Build == other.Build;
    public override bool Equals(object? obj) => obj is Version other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Major, Minor, Build);
    public static bool operator ==(Version left, Version right) => left.Equals(right);
    public static bool operator !=(Version left, Version right) => !left.Equals(right);
}

public class VersionConverter : JsonConverter<Version>
{
    public override Version Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            string s = reader.GetString() ?? throw new JsonException("Version string is null");
            var parts = s.Split('.');
            if (parts.Length != 3) throw new JsonException("A version must have exactly three components.");
            return new Version { 
                Major = ushort.Parse(parts[0]), 
                Minor = byte.Parse(parts[1]), 
                Build = byte.Parse(parts[2]) 
            };
        }
        else if (reader.TokenType == JsonTokenType.StartObject)
        {
            ushort major = 0; byte minor = 0; byte build = 0;
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject) return new Version { Major = major, Minor = minor, Build = build };
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    string prop = reader.GetString() ?? "";
                    reader.Read();
                    switch (prop)
                    {
                        case "major": major = reader.GetUInt16(); break;
                        case "minor": minor = reader.GetByte(); break;
                        case "build": build = reader.GetByte(); break;
                    }
                }
            }
        }
        throw new JsonException("Unexpected token type");
    }

    public override void Write(Utf8JsonWriter writer, Version value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(IcfSystemData), typeDiscriminator: "System")]
[JsonDerivedType(typeof(IcfAppData), typeDiscriminator: "App")]
[JsonDerivedType(typeof(IcfPatchData), typeDiscriminator: "Patch")]
[JsonDerivedType(typeof(IcfOptionData), typeDiscriminator: "Option")]
public abstract class IcfData
{
    public abstract bool IsPrerelease { get; }
    public abstract string GetFilename();
}

// 内部数据类通常用于重用，但在 AOT 下多态通常直接打平处理
public class IcfInnerData
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("version")] public Version Version { get; set; }
    [JsonPropertyName("required_system_version")] public Version RequiredSystemVersion { get; set; }
    [JsonPropertyName("datetime")] public DateTime DateTime { get; set; }
    [JsonPropertyName("is_prerelease")] public bool IsPrerelease { get; set; }
}

public class IcfSystemData : IcfData
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("version")] public Version Version { get; set; }
    [JsonPropertyName("required_system_version")] public Version RequiredSystemVersion { get; set; }
    [JsonPropertyName("datetime")] public DateTime DateTime { get; set; }
    [JsonPropertyName("is_prerelease")] public bool IsPrereleaseValue { get; set; }
    public override bool IsPrerelease => IsPrereleaseValue;
    public override string GetFilename() => $"{Id}_{Version.Major:D4}.{Version.Minor:D2}.{Version.Build:D2}_{DateTime:yyyyMMddHHmmss}_0.pack";
}

public class IcfAppData : IcfData
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("version")] public Version Version { get; set; }
    [JsonPropertyName("required_system_version")] public Version RequiredSystemVersion { get; set; }
    [JsonPropertyName("datetime")] public DateTime DateTime { get; set; }
    [JsonPropertyName("is_prerelease")] public bool IsPrereleaseValue { get; set; }
    public override bool IsPrerelease => IsPrereleaseValue;
    public override string GetFilename() => $"{Id}_{Version}_{DateTime:yyyyMMddHHmmss}_0.app";
}

public class IcfOptionData : IcfData
{
    [JsonIgnore] public string AppId { get; set; } = "";
    [JsonPropertyName("option_id")] public string OptionId { get; set; } = "";
    [JsonIgnore] public Version RequiredSystemVersion { get; set; } = new Version();
    [JsonPropertyName("datetime")] public DateTime DateTime { get; set; }
    [JsonPropertyName("is_prerelease")] public bool IsPrereleaseValue { get; set; }
    public override bool IsPrerelease => IsPrereleaseValue;
    public override string GetFilename() => $"{AppId}_{OptionId}_{DateTime:yyyyMMddHHmmss}_0.opt";
}

public class IcfPatchData : IcfData
{
    [JsonIgnore] public string Id { get; set; } = "";
    [JsonPropertyName("sequence_number")] public byte SequenceNumber { get; set; }
    [JsonPropertyName("source_version")] public Version SourceVersion { get; set; }
    [JsonPropertyName("source_datetime")] public DateTime SourceDateTime { get; set; }
    [JsonPropertyName("source_required_system_version")] public Version SourceRequiredSystemVersion { get; set; }
    [JsonPropertyName("target_version")] public Version TargetVersion { get; set; }
    [JsonPropertyName("target_datetime")] public DateTime TargetDateTime { get; set; }
    [JsonPropertyName("target_required_system_version")] public Version TargetRequiredSystemVersion { get; set; }
    [JsonPropertyName("is_prerelease")] public bool IsPrereleaseValue { get; set; }
    public override bool IsPrerelease => IsPrereleaseValue;
    public override string GetFilename() => $"{Id}_{TargetVersion}_{TargetDateTime:yyyyMMddHHmmss}_{SequenceNumber}_{SourceVersion}.app";
}