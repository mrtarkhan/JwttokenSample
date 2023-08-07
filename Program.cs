// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string secretKey = "we-need-a-secret-key-for-signing-our-jwt";

string token = BuildJwt();

ParseJWT(token);

static string Base64UrlEncode(string input)
{

    var inputBytes = Encoding.UTF8.GetBytes(input);

    var base64 = Convert.ToBase64String(inputBytes);

    /*
    This replacement is necessary to ensure that the resulting Base64 string is URL-safe
    and does not contain any characters that may cause issues when used in URLs or certain contexts
     */

    var base64Url = base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');

    return base64Url;

}

static string ComputeSignature(string input)
{


    var keyBytes = Encoding.UTF8.GetBytes(secretKey);

    using var algorithm = new HMACSHA256(keyBytes);

    var inputBytes = Encoding.UTF8.GetBytes(input);

    var signatureBytes = algorithm.ComputeHash(inputBytes);

    return Base64UrlEncode(Encoding.UTF8.GetString(signatureBytes));

}

static string Base64UrlDecode(string input)
{
    string base64 = input.Replace('-', '+').Replace('_', '/');

    // we have to add all = signs we have removed based on base64 algorithm
    while (base64.Length % 4 != 0)
    {
        base64 += '=';
    }

    var base64Bytes = Convert.FromBase64String(base64);

    return Encoding.UTF8.GetString(base64Bytes);

}

static string BuildJwt()
{
    Dictionary<string, string> headers = new Dictionary<string, string>
{
    { "alg", "HS256" },
    { "typ", "JWT" }
};

    Dictionary<string, string> payload = new Dictionary<string, string>
{
    { "sub", "1234567890" },
    { "name", "Mohammadreza Tarkhan" },
    { "role", "admin" }
};

    string encodedHeader = Base64UrlEncode(JsonSerializer.Serialize<Dictionary<string, string>>(headers));
    string encodedPayload = Base64UrlEncode(JsonSerializer.Serialize<Dictionary<string, string>>(payload));

    string unsignedToken = $"{encodedHeader}.{encodedPayload}";

    string signature = ComputeSignature(unsignedToken);

    string jwt = $"{unsignedToken}.{signature}";

    Console.WriteLine(jwt);

    Console.WriteLine();

    return jwt;
}

static void ParseJWT(string jwt)
{
    string[] jwtParts = jwt.Split('.');

    string header = Base64UrlDecode(jwtParts[0]);

    string payload = Base64UrlDecode(jwtParts[1]);

    string signature = jwtParts[2];

    string expectedSignature = ComputeSignature($"{jwtParts[0]}.{jwtParts[1]}");

    if (expectedSignature == signature)
    {
        Console.WriteLine("JWT signature is valid.");
    }
    else
    {
        Console.WriteLine("JWT signature is invalid.");
    }

    Console.ReadLine();
}