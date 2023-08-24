import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.jcajce.provider.symmetric.ARC4.Base;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;



public class TestAI {
	private static KeyPair ECKeyPair;
	private static KeyPair XECKeyPair;
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, IOException, InvalidParameterSpecException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		try {
			XECgenkeypair();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		double version = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getVersion();
		System.out.println("BC version :" + version);
		
		KeyPairGenerator aliceKpairGEN = KeyPairGenerator.getInstance("ECDH");
		//创建alice密钥对
		ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp256r1");
		aliceKpairGEN.initialize(parameterSpec);
		//初始化alice密钥参数
		KeyPair aliceKeyPair = aliceKpairGEN.generateKeyPair();
		//alice生成了密钥对
		KeyAgreement aliceAgree = KeyAgreement.getInstance("ECDH");
		aliceAgree.init(aliceKeyPair.getPrivate());
		//生成alice的Agreement对象
		byte[] alicePub_trans = aliceKeyPair.getPublic().getEncoded();
		//模拟alice的公钥在信道传递
		
		
		//   A -> B 
		
		
		//bob收到了alice的公钥（编码的）
		KeyFactory bobKeyfac = KeyFactory.getInstance("ECDH");
		X509EncodedKeySpec x509keysp = new X509EncodedKeySpec(alicePub_trans);
		PublicKey alice_pubkey = bobKeyfac.generatePublic(x509keysp);
		//bob封装密钥,得到alice公钥
		ECParameterSpec ecFromAlice = ((ECPublicKey)alice_pubkey).getParams();
//		AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("XDH","BC");
//		algorithmParameters.init(alice_pubkey.getEncoded());
//		ECParameterSpec ecFromAlice = algorithmParameters.getParameterSpec(ECParameterSpec.class);
		
		//得到alice的EC参数
		
		//接下来bob创建自己的密钥对
		KeyPairGenerator bobKeypairGEN  = KeyPairGenerator.getInstance("ECDH");
		bobKeypairGEN.initialize(ecFromAlice);
		KeyPair bobKeyPair = bobKeypairGEN.generateKeyPair();
		//bob成功生成参数和alice相同的密钥对
		
		//bob创建自己的agree对象
		KeyAgreement bobAgree = KeyAgreement.getInstance("ECDH");
		bobAgree.init(bobKeyPair.getPrivate());
		//bob把自己的公钥发给alice
		byte[] bobPubkey_trans = bobKeyPair.getPublic().getEncoded(); 
		//模拟传输
		
		
		//   B -> A
		
		
		//接下来alice收到了bob公钥（数组）
		//alice也是把其先封装为密钥
		KeyFactory aliceKeyFac = KeyFactory.getInstance("ECDH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubkey_trans);
		PublicKey bobPublicKey = aliceKeyFac.generatePublic(x509KeySpec);
		//接下来钟老师的注释是这样写的：Alice使用Bob的公钥进行共享密钥生成的一下操作
		//看起来好像是alice同意了密钥
		aliceAgree.doPhase(bobPublicKey, true);
		// Bob使用Alcie的公钥进行共享密钥生成的一下操作
		bobAgree.doPhase(alice_pubkey, true);
		
		
		//会话密钥生成环节
		
		byte[] aliceSharedSecret = aliceAgree.generateSecret();
        byte[] bobSharedSecret = bobAgree.generateSecret();
        
        //那么这俩数组应该是一样的。可以拿去制作会话密钥
        System.out.println(Hex.toHexString(aliceSharedSecret));
        System.out.println(Hex.toHexString(bobSharedSecret));
		
		
	}
	


    public static String generateECCKeyPair() {
    	//int keysize = 256; //192、239、256、224、384、521
       
            try {
				// 获取指定算法的密钥对生成器
				KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
				// 初始化密钥对生成器（指定密钥长度, 使用默认的安全随机数源）
				ECGenParameterSpec secp = new ECGenParameterSpec("secp521r1");
				generator.initialize(secp,new SecureRandom());
				// 随机生成一对密钥（包含公钥和私钥）
				ECKeyPair = generator.generateKeyPair();
				ECPublicKey ecpub = (ECPublicKey)ECKeyPair.getPublic();
				ECPrivateKey ecpri = (ECPrivateKey)ECKeyPair.getPrivate();
				
				//System.out.println("EC pub = " + ecpub);
				
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
        
        return "Error";
    }

    public static  void XECgenkeypair() throws Exception {
		// 用X448或X25519初始化ECGenParameterSpec
		ECGenParameterSpec parameterSpec = new ECGenParameterSpec("X25519");
		KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
		generator.initialize(parameterSpec);
		XECKeyPair = generator.generateKeyPair();
		XECPublicKey publicKey = (XECPublicKey) XECKeyPair.getPublic();
		XECPrivateKey privateKey = (XECPrivateKey) XECKeyPair.getPrivate();
		System.out.println("XEC pub = " + publicKey.getU());
		//System.out.println("私钥: " + Hex.toHexString(privateKey.getEncoded()));
	}
    
    
    
    
    
    
    
    
    
    
    
    
    
}




