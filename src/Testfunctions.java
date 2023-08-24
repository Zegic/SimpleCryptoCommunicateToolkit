import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jcajce.provider.symmetric.ARC4.Base;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class Testfunctions {
	private static KeyPair rsaKeyPair;
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		String en = "qweqweqweqweqwe";
		byte[] enc = en.getBytes();
		System.out.println(enc);
		System.out.println(decrypt_by_my_rsa_prikey(encrypt_use_his_rsa_pubkey(get_my_rsa_pubkey(), en)));
	}



public static String get_my_rsa_pubkey(  ) {
	
	KeyPairGenerator kpg = null;
	try {
		kpg = KeyPairGenerator.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	rsaKeyPair = kpg.generateKeyPair();
	PublicKey publicKey = rsaKeyPair.getPublic();
	String encodekey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
	//把rsa密钥编码成base64发出
	System.out.println(encodekey);
	return encodekey;
	
}

public static String encrypt_use_his_rsa_pubkey( String input_pubkey , String plain ) {
	byte[] unpack_key = Base64.getDecoder().decode(input_pubkey);
	PublicKey pubkey = null;
	try {
		pubkey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unpack_key));
	} catch (InvalidKeySpecException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	//上面是把base64的rsa公钥封装成rsa公钥
	
	//下面是用这个公钥加密
	byte[] cipherText = null;
	
	try {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pubkey);
		cipherText = cipher.doFinal(plain.getBytes());
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	String output = Base64.getEncoder().encodeToString(cipherText);
	System.out.println(output);
	return output;
}

public static String decrypt_by_my_rsa_prikey( String input_cipher) {
	byte[] input = Base64.getDecoder().decode(input_cipher);
	PrivateKey prikey = rsaKeyPair.getPrivate();
	byte[] plain = null;
	
	try {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, prikey);
		plain = cipher.doFinal(input);
	} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return plain.toString();
}
}