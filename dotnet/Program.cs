using System.Security.Cryptography;

/*
	The keys are base64 RSA dumps X.509 ASN1 dumps with "-----BEGIN/END RSA PRIVATE/PUBLIC KEY-----" ommited.
	You can generate this with openssl library (multiplatform).
*/

const string PRIVATE_KEY = "MIIEowIBAAKCAQEAqntU3ijCZhBEdQDiecl2tFqDXyISBF+cqlG2cAak1UF4RPV6\r\nljmOe3dquX/kLgM8B0jsnEwOYmW2lHUKvdaOUyj8kd/wXHJTDZJ9NSIG1I/GZmx9\r\nMIxl2q4vu2Ia18CzQggNUP6N2bJM8L9px9wGchFNljimN4mUttRo/apHi9iueE6H\r\nRl0MPV3Lb3JmKCCWxJb2xQOfDfhz7esm4SqgnKUcPl/vf7slJm3L+Hd1QW6zkaFi\r\nInELsopCiM5YPTLwfpz2lX40QhrQsj0zu7kCVysIX9JsTfFSrz4NuRoZ15uDsRvs\r\nDQsiyoYurkIXpggO6IQwegDgV/gMiby6G3eJAQIDAQABAoIBAC4yU3IL+3mqyNIn\r\n1jcIR7lhmZ3K3rT+r7ZbhCNhOYNsRUnydzCEEj8Uwf/YTx3E1Jxov20vEurJAyvB\r\nd5KvtEuGnMJuu3Rhqm3QF0uxl8Y725hfp6DjOqqCbv7I+9shJbIr+mfLQucN8NmA\r\nFQsKbVi1pZ+iZDBCgOD2OCkc3lxffcMJW9W5KqPNjUt/UgfIF4+miprYdUpOicZD\r\n6/RMc7/nGuiiwwByl9qCtHadzEA8TL4YEnmu5WUlT0ixTay4KHvPNs/l7ewvUu3/\r\nJfrU8oUP9mP35UGzE3iuxQPim+ZatKwrI+C+jnZCGlHcZHAqo6ayWlO/s3HZ3/VF\r\nrg1rrz0CgYEA78yz5r33ObgMOygWOrTaJzOQt0wbKgasTvNtYLTq7wqVhYrrr2Mb\r\nxOb8L4oq3NZS7Cr8Dv6T3b4WAiINYxr5lWY4ONzl6w8WxgrlHiNBd1ovqCtZtQTO\r\nDzFa7WhDUD9pHxppQI9F486G8gNwpFlNv+4bML35N+liLcPmo1UfCFcCgYEAtf/J\r\nhYvbfRUJICu7ScdJCj7e3KLMOuyS9xywSCqKvRVMmLy+BLQh5sicbLY6N8c6cL7P\r\n3sxfZCBwcJO4hPQ97CuryOfaCU8xqgYYH9Smzi1sr/clIhu9SbGbBo+M+F9ZUEs4\r\n9iKPINhEmD9qGnNcBWmUj7oKSwrMcvHdmDjZgmcCgYBL5vdqqeZ/FoqIjv+6RVRn\r\n5CKCYkyW2NXhh5uvaJSUZT0+r+I5+ZzojlR0l79Jd21344M1G8+h+HDu6+hg3kDx\r\n0REqroD4DiafOQOcrnwiUyGSkWYrrgGrPWwSiVYFKI0Vkz6NeMwed1ivcfdNjhbW\r\nEX/5xagE0pKI+eEfAep4sQKBgA5OrWjyNa7/mFgPGAoUwIktqBdwNN3s+yCyAKmr\r\nrnxu0Daxn75+6qtZ2fIx4SHBZ7a1SWIabuVQJ4ayFi9dhACs7jQ9Bcb1ktHq6LqX\r\n3QUYTRMIOsMTqy2/6I/7ePmNhVfqke/Hh7jtR3cwhQbPSsyiICusVGLR1oCywtjU\r\nn0TBAoGBALQHhvGvlyuq4cXBTJCtLoyDEaiitt0jHgNLqAnyenddn7N0iNxZrHGw\r\nWCsmL7IMgEZTkyD4Bqzozshfq0ju2eIeGks1y54JA7ULI2kZZdjRK4wybO3TLRep\r\nLwCHeNOSSuG84gfA26991uK0om8SgGxP4cRrB7GcR3geyKDQobKi";
const string PUBLIC_KEY = "MIIBCgKCAQEAqntU3ijCZhBEdQDiecl2tFqDXyISBF+cqlG2cAak1UF4RPV6ljmO\r\ne3dquX/kLgM8B0jsnEwOYmW2lHUKvdaOUyj8kd/wXHJTDZJ9NSIG1I/GZmx9MIxl\r\n2q4vu2Ia18CzQggNUP6N2bJM8L9px9wGchFNljimN4mUttRo/apHi9iueE6HRl0M\r\nPV3Lb3JmKCCWxJb2xQOfDfhz7esm4SqgnKUcPl/vf7slJm3L+Hd1QW6zkaFiInEL\r\nsopCiM5YPTLwfpz2lX40QhrQsj0zu7kCVysIX9JsTfFSrz4NuRoZ15uDsRvsDQsi\r\nyoYurkIXpggO6IQwegDgV/gMiby6G3eJAQIDAQAB";
const string CLIENT_ID = "gameProviderXY";
const string MESSAGE = "Příliš žluťoučký kůň úpěl ďábelské ódy.";
const string HTTP_HEADER_NAME = "X-gameprovider-signature";

byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(MESSAGE);

// sign our MESSAGE using only PRIV_KEY
var signatureHeader = SignMessage(messageBytes);
Console.WriteLine($"Header '{HTTP_HEADER_NAME}' = '{signatureHeader}'");

// verify MESSAGE signature using only PUB_KEY
var verified = VerifySignature(messageBytes, signatureHeader);
Console.WriteLine($"Verification result: {verified}");

string SignMessage(byte[] message)
{
    using var rsa = RSA.Create();
    rsa.ImportRSAPrivateKey(Convert.FromBase64String(PRIVATE_KEY), out _);
    var result = CLIENT_ID + "," + Convert.ToBase64String(rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    return result;
}

bool VerifySignature(byte[] message, string signatureHeader)
{
    using var rsa = RSA.Create();
    rsa.ImportRSAPublicKey(Convert.FromBase64String(PUBLIC_KEY), out _);
    var signature = signatureHeader.Split(',', 2)[1];
    return rsa.VerifyData(message, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}