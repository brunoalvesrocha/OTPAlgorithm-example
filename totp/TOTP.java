import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/*
  Autor: Allan Romanato
  Data: 26/05/2015
*/

public class TOTP {

	public static String getToken() throws NoSuchAlgorithmException {

		String secretSeed = convertStringToHex("12345678901234567890");
//		int secretSeedGeneration = new Random().nextInt(2000000000);
		System.out.println("Random value: " + secretSeed);
//		String secretSeed = convertStringToHex(String.valueOf(secretSeed));
		String result = null;
		long timeWindow = 60L;
		long exactTime = System.currentTimeMillis() / 1000L;
		long preRounded = (long) (exactTime / timeWindow);
		String roundedTime = Long.toHexString(preRounded).toUpperCase();

		while (roundedTime.length() < 16) {
			roundedTime = "0" + roundedTime;
		}

		byte[] hash = HMAC.hmac(hexStr2Bytes(secretSeed), hexStr2Bytes(roundedTime));
		int offset = hash[hash.length - 1] & 0xf;
		int otp = ((hash[offset + 0] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
		otp = otp % 1000000;

		result = Integer.toString(otp);
		while (result.length() < 6) {
			result = "0" + result;
		}

		return result;
	}

	private static byte[] hexStr2Bytes(String hex) {// Responsavel por Converter HEX em Bytes
		byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
		byte[] ret = new byte[bArray.length - 1];
		for (int i = 0; i < ret.length; i++)
			ret[i] = bArray[i + 1];
		return ret;
	}
 
	public static String convertStringToHex(String str) {// Responsavel por converter String para HEX

		char[] chars = str.toCharArray();

		StringBuffer hex = new StringBuffer();
		for (int i = 0; i < chars.length; i++) {
			hex.append(Integer.toHexString((int) chars[i]));
		}

		return hex.toString();
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InterruptedException {
		int qtn = 1;
		while (true) {
			System.out.println(qtn++ + " = " + (System.currentTimeMillis() / 1000L) + " -> " + getToken());
			Thread.sleep(60000);
		}
	}

}
