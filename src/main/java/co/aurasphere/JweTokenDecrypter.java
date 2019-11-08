package co.aurasphere;

import java.util.Scanner;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;

/**
 * Decrypter for a JWE token.
 * 
 * @author Donato Rimenti
 */
public class JweTokenDecrypter {

	/**
	 * Decrypts a JWE token and prints its content.
	 * 
	 * @param args null
	 * @throws JoseException if the token is invalid
	 */
	public static void main(String[] args) throws JoseException {
		System.out.println("JWE token decrypter");
		System.out.print("Enter decrypt key: ");
		try (Scanner s = new Scanner(System.in)) {
			String key = s.nextLine();
			while (true) {
				System.out.print("Enter JWE token to decrypt: ");
				String token = s.nextLine();
				System.out.println("Decrypted token: ");
				System.out.println(decryptToken(token, key));
			}
		}
	}

	/**
	 * Decrypts a token and returns its string representation in JSON format
	 * (headers + payload). The JSON is not formally valid.
	 * 
	 * @param token the token to decrypt
	 * @param key   the key used to decrypt the token
	 * @return a string representation of the token to decrypt
	 * @throws JoseException if the token is invalid
	 */
	static String decryptToken(String token, String key) throws JoseException {
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setKey(new AesKey(key.getBytes()));
		jwe.setCompactSerialization(token);
		return jwe.getHeaders().getFullHeaderAsJsonString() + jwe.getPayload();
	}

}