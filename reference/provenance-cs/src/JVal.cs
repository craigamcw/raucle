using System.Text.Json;

namespace Raucle.Provenance;

/// <summary>
/// Minimal JSON value model used for canonical encoding. Kept separate
/// from System.Text.Json so the canonical byte output is fully under
/// our control (sorted keys, integer-only numbers, fixed escaping).
/// </summary>
public abstract record JVal
{
    public static JVal Of(string s) => new JStr(s);
    public static JVal Of(long i) => new JInt(i);
    public static JVal Of(bool b) => new JBool(b);
    public static JVal Arr(IEnumerable<JVal> items) => new JArr(items.ToList());
    public static JVal Arr(IEnumerable<string> items) => new JArr(items.Select(x => (JVal)new JStr(x)).ToList());

    /// <summary>Build a JVal from a parsed System.Text.Json element (used on verify).</summary>
    public static JVal FromJsonElement(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => new JNull(),
        JsonValueKind.True => new JBool(true),
        JsonValueKind.False => new JBool(false),
        JsonValueKind.String => new JStr(e.GetString()!),
        JsonValueKind.Number => e.TryGetInt64(out var l)
            ? new JInt(l)
            : throw new InvalidOperationException("canonical-JSON: only integer numbers are supported in v1"),
        JsonValueKind.Array => new JArr(e.EnumerateArray().Select(FromJsonElement).ToList()),
        JsonValueKind.Object => new JObj(
            e.EnumerateObject().ToDictionary(p => p.Name, p => FromJsonElement(p.Value))),
        _ => throw new InvalidOperationException($"canonical-JSON: unsupported JSON kind {e.ValueKind}"),
    };
}

public sealed record JNull : JVal;
public sealed record JBool(bool Value) : JVal;
public sealed record JInt(long Value) : JVal;
public sealed record JStr(string Value) : JVal;
public sealed record JArr(List<JVal> Items) : JVal;

public sealed record JObj(Dictionary<string, JVal> Members) : JVal
{
    public JObj() : this(new Dictionary<string, JVal>()) { }

    public JObj Set(string key, JVal value)
    {
        Members[key] = value;
        return this;
    }

    public bool TryGet(string key, out JVal value) => Members.TryGetValue(key, out value!);

    public string? Str(string key) =>
        Members.TryGetValue(key, out var v) && v is JStr s ? s.Value : null;

    public IReadOnlyList<string>? StrArray(string key) =>
        Members.TryGetValue(key, out var v) && v is JArr a
            ? a.Items.Select(x => x is JStr s ? s.Value : string.Empty).Where(s => s != null).ToList() as IReadOnlyList<string>
            : null;
}
