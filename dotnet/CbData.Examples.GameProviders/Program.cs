using System.Security.Cryptography;

/*
	The keys are base64 RSA dumps X.509 ASN1 dumps with "-----BEGIN RSA PUBLIC KEY-----" & "-----END RSA PUBLIC KEY-----" ommited
	go to https://8gwifi.org/PemParserFunctions.jsp, select RSA PUBLIC KEY from dropdow, and try pasting the PUB_KEY in the following format to inspect it (leave "cert password" empty):
		-----BEGIN RSA PUBLIC KEY-----
		MIIBCgKCAQEAs8vblUD7TY9UbTu9Kt2LKFPi7Fy1YgXHT5rz+FuaUr6ci8EtTfkxpuPg4lmBSOqqQ8w2r8GVhzlxGkpS3SOsu93P17hFX78eT5T+FM2drrNkHnd61LsDErp/GSDvoUVjtfcbfYVNjKY0zMD4uQQJnBZYU1HhwAZPT3HEjVRAYrVi7SBwt60BSbVe2yOG9a8ByPLUonKMmoqOhgdJAwNTb/1wuudnussV57O8lbrXhppdLOUPoV9HF3gUi0tdT23/dwlYE8dmpw4ZwepjZd0I6y5uT6bdOczj4aMc/9wULzTVLTulpxfFPgy6DUNne5aYBiIFKecbRHRWaJbDQrX4IQIDAQAB
		-----END RSA PUBLIC KEY-----
*/

const string PRIV_KEY = "MIIEpAIBAAKCAQEAs8vblUD7TY9UbTu9Kt2LKFPi7Fy1YgXHT5rz+FuaUr6ci8EtTfkxpuPg4lmBSOqqQ8w2r8GVhzlxGkpS3SOsu93P17hFX78eT5T+FM2drrNkHnd61LsDErp/GSDvoUVjtfcbfYVNjKY0zMD4uQQJnBZYU1HhwAZPT3HEjVRAYrVi7SBwt60BSbVe2yOG9a8ByPLUonKMmoqOhgdJAwNTb/1wuudnussV57O8lbrXhppdLOUPoV9HF3gUi0tdT23/dwlYE8dmpw4ZwepjZd0I6y5uT6bdOczj4aMc/9wULzTVLTulpxfFPgy6DUNne5aYBiIFKecbRHRWaJbDQrX4IQIDAQABAoIBAQCRh+XR9soy6lwlGqCwrKhx2Qyp0xTCJflBNyRZGBRe+4iNGq0IGzeUZYlmzZn3InL087wkISZeUSF6bUSLWM/9NLqCWtZUfMcVFX1f61rByNS2UHGs9T60jx5HgcBVImxmIoEu5ZJy0SmVvnDUmS8KF5AgyPtYygKyRF0bJGIFQn4/IBFo8SSAP3nyOcWeW+GSGXzq5U/aOHmFHVQLcGeRgN7iT9GYHupDXOxEItYLfcfGBkFhuSadDH3KvEMAmAyiJwG1ku/634R2nDfFfe9bzS2hjDDBAYfpoO1Y3LkB603UK1I5L3Xlip5o0yk2ECgc+ZpYdftwwlIPjcQSgNqdAoGBAMXWpJ+6LKAiI20/Uc30Rp4krxnSiTQ7xKCbe6awb6IrO0CLx1LJrHqyWh03nl1zWhaKJV174UA6M3+okhgnc4GDjhURamZwnvOhHt9MN+xIxx1+rJWLS6STRmjo5ljxvLCAQjQZOxBivNPADVdfw7Ind+z3g4XadqY1D19wSYnfAoGBAOinXFqLBzuKH/qf+cdKIIH1Rt3SgH0y8Bb6HVPXBZa1DO4WacxK/XDXJIKnNq98nbHQtygqBqz2JRuXE8u6Ms3vS1nN1IRBV9kLEf3jYkTXHoUDwblF4La8p3smWXCtPZ2osDGr0DFHPHr7HC0z+Ix/heOVn2HIanXXmJxO1L3/AoGBAMRmBR+cDtkZitnVVjyDF+e+uyWDYDm+a8CVGfesh+YRzMyS9tk05EkZ7WO75zcWYISnt9hKNp8wKBe/HOlloMEd/Frl4x63BtUNSjyayZmD1kdtjZ8XnYxPuEJFkwcRVCRT72UQ9xWZL6N2sMfghcHCdMeGH8ctzUPKwOwZ6Kc5AoGAVEllxQu/SAvHgCX6+P9a/Zod3XlIwZL1tm1QuLIavTnEgHEwTSoR3ZKkEI2B21vbSbNi17M6DelzEibOri08AK2j79oJFw0RRXmkQAXj8Sq6TNhKk9PEEJASYSRInPC2dOrLQoOLfn7fY3KcB6hfcI82s3fecS+Jmj3MdTx+CIMCgYBLzx6QSBwIUzONwoG39SZ5My1HX7mf4R1+hwPU5lqifnIkRzoWReFf8RpR+Yg4pKJPX75XIFkdNBzyjXn0np93TBqyU5NkXcr6+VqIIVGXNwoJh7eGcGiCvVThUE6G7pxQhtM4DRpRjX5TtCM4JyIHW8gJPVsTxAcZTU8lN6yAig==";
const string PUB_KEY = "MIIBCgKCAQEAs8vblUD7TY9UbTu9Kt2LKFPi7Fy1YgXHT5rz+FuaUr6ci8EtTfkxpuPg4lmBSOqqQ8w2r8GVhzlxGkpS3SOsu93P17hFX78eT5T+FM2drrNkHnd61LsDErp/GSDvoUVjtfcbfYVNjKY0zMD4uQQJnBZYU1HhwAZPT3HEjVRAYrVi7SBwt60BSbVe2yOG9a8ByPLUonKMmoqOhgdJAwNTb/1wuudnussV57O8lbrXhppdLOUPoV9HF3gUi0tdT23/dwlYE8dmpw4ZwepjZd0I6y5uT6bdOczj4aMc/9wULzTVLTulpxfFPgy6DUNne5aYBiIFKecbRHRWaJbDQrX4IQIDAQAB";
const string CLIENT_ID = "gameProviderXY";
const string MESSAGE = "Příliš žluťoučký kůň úpěl ďábelské ódy.";
const string HTTP_HEADER = "X-gameprovider-signature";

byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(MESSAGE);

// sign our MESSAGE using only PRIV_KEY
var signatureHeader = SignMessage(messageBytes);
Console.WriteLine($"Header '{HTTP_HEADER}' = '{signatureHeader}'");

// verify MESSAGE signature using only PUB_KEY
var verified = VerifySignature(messageBytes, signatureHeader);
Console.WriteLine($"Verification result: {verified}");

string SignMessage(byte[] message)
{
    using var rsa = RSA.Create();
    rsa.ImportRSAPrivateKey(Convert.FromBase64String(PRIV_KEY), out _);
    var result = CLIENT_ID + "," + Convert.ToBase64String(rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    return result;
}

bool VerifySignature(byte[] message, string signatureHeader)
{
    using var rsa = RSA.Create();
    rsa.ImportRSAPublicKey(Convert.FromBase64String(PUB_KEY), out _);
    var signature = signatureHeader.Split(',', 2)[1];
    return rsa.VerifyData(message, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}