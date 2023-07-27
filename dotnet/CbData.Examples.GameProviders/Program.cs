using System.Security.Cryptography;

/*
	The keys are base64 RSA dumps X.509 ASN1 dumps with "-----BEGIN/END RSA PRIVATE/PUBLIC KEY-----" ommited.
	You can generate this with openssl library (multiplatform).
*/

const string PRIVATE_KEY = "MIIEowIBAAKCAQEAvKlOt0yROi7ccHNU6ce0BVaJx34i39if0QEk1r1iyN/2Q0a4\r\nQbnPfYMRVHTwafGJWmNvWcrDXndmSCPACxUkpalS86E1puI7XDGVWMD3VKboaV/R\r\nRnMrHLuk7wjLWN4YYl68CTLr7xOuZjb9F/6xfALZaqXJPb9XM9KDhheAc68K94k5\r\nJyV6CwZj1ne9qlIxe+jlpM2K6ww9uqcfYgetNXM5cNlIcDw+YsVOQqnjX00cK0e/\r\nyvZW/1bmw+FBCLif0ckJjKdg5RaijxuI/0gw/O7y1BZcTz+dP43G3+zPsU7V8Tf7\r\n+WRWCbmx9IOI0Rotc4FQtdqIgpxhH/cE4MhRrwIDAQABAoIBADLDU5zai1Eefs37\r\nGmP1CilNibEV7YhRn177cdAeEVB/gqHDi5yTxJK/C5CwDmhTR2P80V9VwY/PjMPo\r\naqoQvFWe4+UOAYOv58z8wnSpJ2OtrWd9ErBkGLuYed6ffSeiSuldGDdZbkZcA1cZ\r\ngKxOKa92jM23YhitPWeCQ0V3WWbGwhi3KtCD9luXfuQXaJSEDfT5TIS9x3A2k6uM\r\nlq4Dcf6dRQK9XEGe9amiy+LGSlMYod7F4HEXEyZF6nckI+OF/IJZgnJv66MQB8g4\r\nCzZlbZ5TUlT4oDwQgKza5IftewMBV712/4txlvYyNu8qMHj6vf0Cjyfmiol5Ip8h\r\npTNngkECgYEA7BWlMR8douhJ2Cw4X1wNVjkfeodQER670dA9hXvOtUrZ9BLJQRzW\r\nxR/oJwdoaCZ5i4NP1UXAtbDLDKqX3BzHKMaCbhjRMxHkXeWbVRgwipZuxba1py0U\r\nn6+2PX6WjwTuyXj9+aYpus6gh3fuoBjI3jt0V8R+dN09ev6RdOK38R8CgYEAzJOJ\r\nVVsPFh5iJzXmkfW0HG3bMfHu/9KsLFtLzuENcfLp0and/La8YqJpKoTE9s2WQi8D\r\nVpLrwxVyyL/ooqAil2m5zksRAKHt2ZP9D4ty/krYjHX6Zn9Fmst06g3kBBmDDcsj\r\nqqmevdftZOJ6Qqcj8Wk6SxrL+HgcNGAbqf4NvXECgYEA4b703dq+EQeDjRUDtpOk\r\nIR2wLw7yjdxQhplUKq6vgwWXEd9g2EVGTOpsp91ahbS8pp4imXIAivwJvQvm+FAA\r\nVMo08CgE6ouiTfL/LEhcKjkcpSxH2RqvTN7NKVJBj3KNDtQGL1EnN/za3Y7d+/KX\r\nKIG7hy1aKk9fuZtw5U7hyssCgYBT/PZS/rFw6URuyKhCoFcznL5zANqYWMuq4kh7\r\nRNYaRBpOo6ipifRJolf+xsd+c+UOgvKh5mu4ieO4G2HM8mWBODy6PwNZ+SEHRMSO\r\nTzgEwoGpGP6WegX/iSwUs2M7c6XkUdPwyvaLBk1GL9z15FzTTdpK31OCTP13W0XA\r\nQrctYQKBgES+zDOAc63UF91ZYWPpTk57vWUn2bhwo0RtsfsfN0GJAiHzSZxRVrwA\r\nRNSPNnix5DI8O0In8tB6EZ99OpXFiOBmN21X6BCLN+IYKsGLSTbdh0Fr67FAyer7\r\ndRdx2L+KpB0AKGLBYsHLNtd+GUE0j2rWDYuSFbK0R8m9oXVkGhNz";
const string PUBLIC_KEY = "MIIBCgKCAQEAvKlOt0yROi7ccHNU6ce0BVaJx34i39if0QEk1r1iyN/2Q0a4QbnP\r\nfYMRVHTwafGJWmNvWcrDXndmSCPACxUkpalS86E1puI7XDGVWMD3VKboaV/RRnMr\r\nHLuk7wjLWN4YYl68CTLr7xOuZjb9F/6xfALZaqXJPb9XM9KDhheAc68K94k5JyV6\r\nCwZj1ne9qlIxe+jlpM2K6ww9uqcfYgetNXM5cNlIcDw+YsVOQqnjX00cK0e/yvZW\r\n/1bmw+FBCLif0ckJjKdg5RaijxuI/0gw/O7y1BZcTz+dP43G3+zPsU7V8Tf7+WRW\r\nCbmx9IOI0Rotc4FQtdqIgpxhH/cE4MhRrwIDAQAB";
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