using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Raucle.Provenance;

/// <summary>
/// Raucle Provenance Receipt v1 — C# reference implementation.
/// Spec: https://raucle.com/spec/provenance/v1
///
/// Mirrors the canonical Python reference (raucle/provenance.py)
/// byte-for-byte: same JOSE header (incl. the "raucle/v1":"provenance"
/// tag), same payload field set, string-typed model/tool/corpus,
/// sha256:-prefixed hashes, and the same content-addressed id
/// ("sha256:" + hex(sha256(jws))). A receipt emitted here verifies in
/// the other reference implementations and yields the identical id.
///
/// Ed25519 comes from BouncyCastle (the .NET BCL has no Ed25519);
/// SHA-256 + base64url from the BCL.
/// </summary>
public static class Receipt
{
    private const string JwsTyp = "provenance-receipt/v1";
    private const string Iss = "raucle-detect/provenance";

    private static readonly HashSet<string> ValidOperations = new()
    {
        "user_input", "model_call", "tool_call", "retrieval",
        "guardrail_scan", "agent_handoff", "sanitisation", "merge",
    };
    private static readonly HashSet<string> KnownFields = new()
    {
        "iss", "typ", "iat", "agent_id", "agent_key_id", "operation", "parents",
        "input_hash", "output_hash", "taint", "ruleset_hash",
        "guardrail_verdict", "model", "tool", "corpus", "tenant",
    };

    // ── base64url ──────────────────────────────────────────────────

    public static string B64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    public static string Sha256Hex(byte[] b) =>
        Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    // ── validation (§4) ────────────────────────────────────────────
    // Lenient where the Python reference is lenient: enforces structural
    // invariants (typ literal, required fields per operation, parent
    // rules), not value shapes.

    public static void Validate(JObj p)
    {
        foreach (var k in p.Members.Keys)
            if (!KnownFields.Contains(k) && !k.StartsWith("x_"))
                throw new ProvException($"reserved/unknown field: {k} (§14)");

        if (p.Str("typ") != JwsTyp)
            throw new ProvException($"payload typ must be {JwsTyp}");

        var op = p.Str("operation") ?? "";
        if (!ValidOperations.Contains(op)) throw new ProvException($"unknown operation: {op}");

        bool Has(string key) => !string.IsNullOrEmpty(p.Str(key));

        if (op == "guardrail_scan" && !Has("guardrail_verdict"))
            throw new ProvException("guardrail_scan requires guardrail_verdict (§4)");
        if (op == "guardrail_scan" && !Has("ruleset_hash"))
            throw new ProvException("guardrail_scan requires ruleset_hash (§4)");
        if (op == "model_call" && !Has("model"))
            throw new ProvException("model_call requires model (§4)");
        if ((op is "tool_call" or "sanitisation") && !Has("tool"))
            throw new ProvException($"{op} requires tool (§4)");
        if ((op is "retrieval" or "sanitisation") && !Has("corpus"))
            throw new ProvException($"{op} requires corpus (§4)");

        var parents = p.StrArray("parents") ?? new List<string>();
        if (op == "user_input" && parents.Count > 0) throw new ProvException("user_input must have no parents");
        if (op != "user_input" && parents.Count == 0) throw new ProvException($"{op} requires at least one parent");

        // §4.2/§4.3.1: parents and taint MUST be sorted in UTF-16 code-unit
        // order and unique. StringComparer.Ordinal is UTF-16; a strictly-
        // increasing check enforces sorted AND unique at once.
        foreach (var name in new[] { "parents", "taint" })
        {
            var arr = p.StrArray(name);
            if (arr == null) continue;
            for (int i = 1; i < arr.Count; i++)
                if (StringComparer.Ordinal.Compare(arr[i - 1], arr[i]) >= 0)
                    throw new ProvException(
                        $"{name} must be sorted in UTF-16 code-unit order and unique (§4.3.1)");
        }
    }

    // ── emit / verify ──────────────────────────────────────────────

    public static SignedReceipt Emit(JObj payload, Ed25519PrivateKeyParameters privateKey)
    {
        // Clone the payload before injecting iss/typ so the caller's object
        // is not mutated (parity with the Go and TS implementations).
        var p = new JObj();
        foreach (var (k, v) in payload.Members)
            p.Set(k, v);
        p.Set("iss", JVal.Of(Iss));
        p.Set("typ", JVal.Of(JwsTyp));
        SortStringArray(p, "parents");
        SortStringArray(p, "taint");

        Validate(p);
        var kid = p.Str("agent_key_id") ?? throw new ProvException("missing agent_key_id");

        var header = new JObj()
            .Set("alg", JVal.Of("EdDSA"))
            .Set("typ", JVal.Of(JwsTyp))
            .Set("kid", JVal.Of(kid))
            .Set("crit", JVal.Arr(new[] { "raucle/v1" }))
            .Set("raucle/v1", JVal.Of("provenance"));

        var headerB = Canonical.Encode(header);
        var payloadB = Canonical.Encode(p);
        var signingInput = B64UrlEncode(headerB) + "." + B64UrlEncode(payloadB);

        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        var msg = Encoding.ASCII.GetBytes(signingInput);
        signer.BlockUpdate(msg, 0, msg.Length);
        var sig = signer.GenerateSignature();

        var jws = signingInput + "." + B64UrlEncode(sig);
        return new SignedReceipt(jws, p, "sha256:" + Sha256Hex(Encoding.ASCII.GetBytes(jws)));
    }

    public static SignedReceipt Verify(string jws, Ed25519PublicKeyParameters publicKey)
    {
        var parts = jws.Split('.');
        if (parts.Length != 3) throw new ProvException("JWS must have three segments");
        var (headerB, payloadB, sigB) = (parts[0], parts[1], parts[2]);

        using var headerDoc = JsonDocument.Parse(B64UrlDecode(headerB));
        var header = headerDoc.RootElement;
        if (GetStr(header, "alg") != "EdDSA") throw new ProvException("unsupported alg");
        if (GetStr(header, "typ") != JwsTyp) throw new ProvException("unexpected typ");
        var critOk = header.TryGetProperty("crit", out var crit)
                     && crit.ValueKind == JsonValueKind.Array
                     && crit.GetArrayLength() == 1
                     && crit[0].ValueKind == JsonValueKind.String && crit[0].GetString() == "raucle/v1";
        if (!critOk) throw new ProvException("crit must be exactly ['raucle/v1']");
        if (GetStr(header, "raucle/v1") != "provenance")
            throw new ProvException("header 'raucle/v1' must be 'provenance'");
        var allowedHeaderKeys = new HashSet<string> { "alg", "typ", "kid", "crit", "raucle/v1" };
        foreach (var prop in header.EnumerateObject())
            if (!allowedHeaderKeys.Contains(prop.Name))
                throw new ProvException($"unexpected JOSE header key: {prop.Name}");

        // Canonical byte-equality (spec v1 §4.3, matches the Python reference):
        // the signature binds the on-wire bytes, but a non-canonical header
        // (unsorted keys / extra whitespace) would still verify without
        // re-encoding and comparing — admitting byte-different receipts for the
        // same logical content.
        var canonHeader = Canonical.Encode(JVal.FromJsonElement(header));
        if (!canonHeader.SequenceEqual(B64UrlDecode(headerB)))
            throw new ProvException("JOSE header is not canonical JSON (JCS)");

        var signingInput = Encoding.ASCII.GetBytes(headerB + "." + payloadB);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(signingInput, 0, signingInput.Length);
        if (!verifier.VerifySignature(B64UrlDecode(sigB))) throw new ProvException("signature invalid");

        var payloadBytes = B64UrlDecode(payloadB);
        using var payloadDoc = JsonDocument.Parse(payloadBytes);
        var payload = (JObj)JVal.FromJsonElement(payloadDoc.RootElement);
        if (!Canonical.Encode(payload).SequenceEqual(payloadBytes))
            throw new ProvException("JWS payload is not canonical JSON (JCS)");
        Validate(payload);

        if (GetStr(header, "kid") != payload.Str("agent_key_id"))
            throw new ProvException("header.kid != payload.agent_key_id (§3)");

        return new SignedReceipt(jws, payload, "sha256:" + Sha256Hex(Encoding.ASCII.GetBytes(jws)));
    }

    private static void SortStringArray(JObj p, string key)
    {
        var arr = p.StrArray(key);
        if (arr == null) return;
        var sorted = arr.OrderBy(x => x, StringComparer.Ordinal);
        p.Set(key, JVal.Arr(sorted));
    }

    private static string? GetStr(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>A signed receipt: the Compact JWS, the parsed payload, and the content-addressed id.</summary>
public sealed record SignedReceipt(string Jws, JObj Payload, string Id);

public sealed class ProvException : Exception
{
    public ProvException(string message) : base(message) { }
}
