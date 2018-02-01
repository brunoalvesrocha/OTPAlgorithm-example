import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HMAC {
	private static final int OPAD = 0x5c;
	private static final int IPAD = 0x36;
	private static final int BLOCKSIZE = 64;
	
	//Implemenacao RFC 2104
	public static byte[] hmac(byte[] key, byte[] message) throws NoSuchAlgorithmException{
		byte[] newKey = new byte[64];
		byte[] oKeyPad = new byte[64];
		byte[] iKeyPad = new byte[64];
		byte[] appendedIKey;
		byte[] appendedOKey;
		byte[] sha1IKey;
		int i;
		int x = 0;
		
		//Se a chave eh maior q o block, tira o hash
		if(key.length > BLOCKSIZE)
			key = sha1(key);
		
		//Populamos o array newKey com a chave passada e completamos com o byte 0x00
		for(i=0;i < BLOCKSIZE;i++) {
			if(key.length>i)
				newKey[i]=key[i];
			else
				newKey[i]=0x00;
		}
		
		//Calculamos o Inner Key Pad e o Outer Key Pad utilizando XOR com duas constantes
		for(i=0; i < BLOCKSIZE; i++){
			iKeyPad[i] = (byte) (newKey[i]^IPAD);
			oKeyPad[i] = (byte) (newKey[i]^OPAD);
		}
		
		//Iniciamos o array de Bytes q ira armazenar o append do InnerKey com a menssagem
		appendedIKey = new byte[iKeyPad.length+message.length];
		
		//Populamos esse array
		for(i=0; i<appendedIKey.length; i++){
			if(iKeyPad.length > i){
				appendedIKey[i] = iKeyPad[i];
			}else{
				appendedIKey[i] = message[x];
				x++;
			}
		}
		
		x=0;
		sha1IKey = sha1(appendedIKey);//Executa-se o Hash do InnerKey+Message
		
		//Cria-se o array que ira ser populado com a Outer Key + Hash anterior
		appendedOKey = new byte[oKeyPad.length+sha1IKey.length];
		
		//Popula esse array
		for(i=0; i<appendedOKey.length; i++){
			if(iKeyPad.length>i){
				appendedOKey[i] = oKeyPad[i];
			}else{
				appendedOKey[i] = sha1IKey[x];
				x++;
			}
		}
		//retorna o resultado.
		return sha1(appendedOKey);
	}
	
	public static byte[] sha1(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input);
        return result;
    }
}
