import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Main {
    /*
        The keys are base64 RSA PKCS#8 dumps with "-----BEGIN/END PRIVATE/PUBLIC KEY-----" ommited.
        You can generate this with openssl library (multiplatform).
    */

    private static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqe1TeKMJmEER1AOJ5yXa0WoNfIhIEX5yqUbZwBqTVQXhE9XqWOY57d2q5f+QuAzwHSOycTA5iZbaUdQq91o5TKPyR3/BcclMNkn01IgbUj8ZmbH0wjGXari+7YhrXwLNCCA1Q/o3Zskzwv2nH3AZyEU2WOKY3iZS21Gj9qkeL2K54TodGXQw9XctvcmYoIJbElvbFA58N+HPt6ybhKqCcpRw+X+9/uyUmbcv4d3VBbrORoWIicQuyikKIzlg9MvB+nPaVfjRCGtCyPTO7uQJXKwhf0mxN8VKvPg25GhnXm4OxG+wNCyLKhi6uQhemCA7ohDB6AOBX+AyJvLobd4kBAgMBAAECggEALjJTcgv7earI0ifWNwhHuWGZncretP6vtluEI2E5g2xFSfJ3MIQSPxTB/9hPHcTUnGi/bS8S6skDK8F3kq+0S4acwm67dGGqbdAXS7GXxjvbmF+noOM6qoJu/sj72yElsiv6Z8tC5w3w2YAVCwptWLWln6JkMEKA4PY4KRzeXF99wwlb1bkqo82NS39SB8gXj6aKmth1Sk6JxkPr9Exzv+ca6KLDAHKX2oK0dp3MQDxMvhgSea7lZSVPSLFNrLgoe882z+Xt7C9S7f8l+tTyhQ/2Y/flQbMTeK7FA+Kb5lq0rCsj4L6OdkIaUdxkcCqjprJaU7+zcdnf9UWuDWuvPQKBgQDvzLPmvfc5uAw7KBY6tNonM5C3TBsqBqxO821gtOrvCpWFiuuvYxvE5vwviirc1lLsKvwO/pPdvhYCIg1jGvmVZjg43OXrDxbGCuUeI0F3Wi+oK1m1BM4PMVrtaENQP2kfGmlAj0XjzobyA3CkWU2/7hswvfk36WItw+ajVR8IVwKBgQC1/8mFi9t9FQkgK7tJx0kKPt7cosw67JL3HLBIKoq9FUyYvL4EtCHmyJxstjo3xzpwvs/ezF9kIHBwk7iE9D3sK6vI59oJTzGqBhgf1KbOLWyv9yUiG71JsZsGj4z4X1lQSzj2Io8g2ESYP2oac1wFaZSPugpLCsxy8d2YONmCZwKBgEvm92qp5n8WioiO/7pFVGfkIoJiTJbY1eGHm69olJRlPT6v4jn5nOiOVHSXv0l3bXfjgzUbz6H4cO7r6GDeQPHRESqugPgOJp85A5yufCJTIZKRZiuuAas9bBKJVgUojRWTPo14zB53WK9x902OFtYRf/nFqATSkoj54R8B6nixAoGADk6taPI1rv+YWA8YChTAiS2oF3A03ez7ILIAqauufG7QNrGfvn7qq1nZ8jHhIcFntrVJYhpu5VAnhrIWL12EAKzuND0FxvWS0eroupfdBRhNEwg6wxOrLb/oj/t4+Y2FV+qR78eHuO1HdzCFBs9KzKIgK6xUYtHWgLLC2NSfRMECgYEAtAeG8a+XK6rhxcFMkK0ujIMRqKK23SMeA0uoCfJ6d12fs3SI3FmscbBYKyYvsgyARlOTIPgGrOjOyF+rSO7Z4h4aSzXLngkDtQsjaRll2NErjDJs7dMtF6kvAId405JK4bziB8Dbr33W4rSibxKAbE/hxGsHsZxHeB7IoNChsqI=";
    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqntU3ijCZhBEdQDiecl2tFqDXyISBF+cqlG2cAak1UF4RPV6ljmOe3dquX/kLgM8B0jsnEwOYmW2lHUKvdaOUyj8kd/wXHJTDZJ9NSIG1I/GZmx9MIxl2q4vu2Ia18CzQggNUP6N2bJM8L9px9wGchFNljimN4mUttRo/apHi9iueE6HRl0MPV3Lb3JmKCCWxJb2xQOfDfhz7esm4SqgnKUcPl/vf7slJm3L+Hd1QW6zkaFiInELsopCiM5YPTLwfpz2lX40QhrQsj0zu7kCVysIX9JsTfFSrz4NuRoZ15uDsRvsDQsiyoYurkIXpggO6IQwegDgV/gMiby6G3eJAQIDAQAB";
    private static final String CLIENT_ID = "gameProviderXY";
    private static final String MESSAGE = "Příliš žluťoučký kůň úpěl ďábelské ódy.";
    private static final String HTTP_HEADER_NAME = "X-gameprovider-signature";

    public static void main(String[] args) throws Exception {
        byte[] messageBytes = MESSAGE.getBytes("UTF-8");

        // sign our MESSAGE using only PRIV_KEY
        String signatureHeader = signMessage(messageBytes);
        System.out.println("Header '" + HTTP_HEADER_NAME + "' = '" + signatureHeader + "'");

        // verify MESSAGE signature using only PUB_KEY
        boolean verified = verifySignature(messageBytes, signatureHeader);
        System.out.println("Verification result: " + verified);
    }

    private static String signMessage(byte[] message) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY));
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(message);
        byte[] signature = privateSignature.sign();

        return CLIENT_ID + "," + Base64.getEncoder().encodeToString(signature);
    }

    private static boolean verifySignature(byte[] message, String signatureHeader) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(message);

        byte[] signatureBytes = Base64.getDecoder().decode(signatureHeader.split(",", 2)[1]);
        return publicSignature.verify(signatureBytes);
    }
}