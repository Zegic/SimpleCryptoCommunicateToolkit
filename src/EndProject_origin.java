import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import java.awt.Color;
import javax.swing.JTextPane;
import javax.swing.JTextArea;



public class EndProject_origin extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextField textFieldstringHASH;
	private JTextField textFieldpasswd;
	private JTextField textFieldFileOrText;
	private JTextArea textAreaHASH;
	protected int signal = 0;

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					EndProject_origin frame = new EndProject_origin();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public EndProject_origin() {


		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 805, 216);
		contentPane = new JPanel();
		contentPane.setBackground(new Color(220, 220, 255));
		contentPane.setForeground(new Color(0, 0, 0));
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		

		JComboBox comboBoxChooseFile = new JComboBox();
		comboBoxChooseFile.setBounds(10, 10, 139, 60);
		contentPane.add(comboBoxChooseFile);
		

		textAreaHASH = new JTextArea();
		textAreaHASH.setText("(HASH值将在此显示)");
		textAreaHASH.setBounds(193, 91, 327, 60);
		contentPane.add(textAreaHASH);
		textAreaHASH.setEditable(false);
		textAreaHASH.setLineWrap(true);
		

		textFieldFileOrText = new JTextField();
		textFieldFileOrText.setBounds(218, 11, 562, 60);
		contentPane.add(textFieldFileOrText);
		textFieldFileOrText.setColumns(10);
		

		JComboBox comboBoxFunction = new JComboBox();
		comboBoxFunction.setBounds(10, 91, 139, 60);
		contentPane.add(comboBoxFunction);
		

		JButton btnAction = new JButton("开始");
		btnAction.setBounds(530, 91, 120, 60);
		contentPane.add(btnAction);
		

		JButton btnExit = new JButton("退出");
		btnExit.setBounds(660, 91, 120, 60);
		contentPane.add(btnExit);
		

		JTextPane textHere = new JTextPane();
		textHere.setText("在此输入" + "\r\n" + "字符串");
		textHere.setBounds(159, 15, 63, 50);
		contentPane.add(textHere);
		

		JButton btnChooseFile = new JButton("...");
		btnChooseFile.setBounds(159, 15, 51, 50);
		contentPane.add(btnChooseFile);
		

		JButton btnSig = new JButton("...");
		btnSig.setBounds(152, 100, 34, 38);
		contentPane.add(btnSig);
		

		textFieldpasswd = new JTextField();
		textFieldpasswd.setBounds(186, 91, 334, 60);
		contentPane.add(textFieldpasswd);
		textFieldpasswd.setColumns(10);
		textFieldpasswd.setText("(HASH值将在此显示)");
		

		JTextPane texthash = new JTextPane();
		texthash.setText("字符串HASH值于此输出");
		texthash.setBounds(10, 80, 173, 21);
		texthash.setEditable(false);
		contentPane.add(texthash);
		

		textFieldstringHASH = new JTextField();
		textFieldstringHASH.setBounds(10, 101, 510, 50);
		contentPane.add(textFieldstringHASH);
		textFieldstringHASH.setColumns(10);
		textFieldstringHASH.setEditable(false);
		

		comboBoxFunction.setVisible(true);
		texthash.setVisible(false);
		textFieldstringHASH.setVisible(false);
		textHere.setVisible(false);
		btnSig.setVisible(false);
		textAreaHASH.setVisible(false);
		



		btnChooseFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				if (chooser.showOpenDialog(EndProject_origin.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						textFieldFileOrText.setText(file.getAbsolutePath());
					}
				}
			}
		});
		

		comboBoxChooseFile.setModel(new DefaultComboBoxModel(new String[] { "文件", "字符串" }));
		

		comboBoxChooseFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (comboBoxChooseFile.getSelectedIndex() == 0) {
					comboBoxFunction.setVisible(true);
					texthash.setVisible(false);
					textFieldstringHASH.setVisible(false);
					textFieldpasswd.setVisible(false);
					textHere.setVisible(false);
					btnChooseFile.setVisible(true);
					textAreaHASH.setVisible(true);
					
				}
				if (comboBoxChooseFile.getSelectedIndex() == 1) {
					comboBoxFunction.setVisible(false);
					texthash.setVisible(true);
					textFieldstringHASH.setVisible(true);
					textFieldpasswd.setVisible(false);
					textHere.setVisible(true);
					btnChooseFile.setVisible(false);
					textAreaHASH.setVisible(false);
					btnSig.setVisible(false);
				}
			}
		});
		

		comboBoxFunction.setModel(new DefaultComboBoxModel<>(new String[] { "计算HASH值", "文件加密(ECB)", "文件加密(OFB)","文件解密", "文件数字签名", "数字签名验证" }));

		comboBoxFunction.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				switch (comboBoxFunction.getSelectedIndex()) {
				case 0: {
					textFieldpasswd.setVisible(false);
					textAreaHASH.setVisible(true);
					textFieldpasswd.setText("(HASH值将在此显示)");
					textAreaHASH.setText("(HASH值将在此显示)");
					btnSig.setVisible(false);
					break;
				}
				case 1: {
					textFieldpasswd.setVisible(true);
					textAreaHASH.setVisible(false);
					textFieldpasswd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 2:{
					textFieldpasswd.setVisible(true);
					textAreaHASH.setVisible(false);
					textFieldpasswd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 3: {
					textFieldpasswd.setVisible(true);
					textAreaHASH.setVisible(false);
					textFieldpasswd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 4: {
					textFieldpasswd.setVisible(true);
					textAreaHASH.setVisible(false);
					btnSig.setVisible(true);
					textFieldpasswd.setText("(选择密钥库文件，缺省则使用默认路径)");
					break;
				}
				case 5: {
					textFieldpasswd.setVisible(true);
					textAreaHASH.setVisible(false);
					btnSig.setVisible(true);
					textFieldpasswd.setText("(选择签名文件)");
					break;
				}
				
				default:
					throw new IllegalArgumentException("Unexpected value: " + comboBoxFunction.getSelectedIndex());
				}
			}
		});
		

		btnSig.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				if (chooser.showOpenDialog(EndProject_origin.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						textFieldpasswd.setText(file.getAbsolutePath());
						signal = 1;
					}
				}
			}
		});
		

		btnExit.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				System.exit(0);

			}
		});
		

		btnAction.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (comboBoxChooseFile.getSelectedIndex() == 0) {
					switch (comboBoxFunction.getSelectedIndex()) {
					case 0: {
						HASH_file();
						break;
					}
					case 1: {
						Encrypt();
						break;
					}
					case 2:{
						EncryptOFB();
						break;
					}
					case 3: {
						int signal = 0;
						try {
							FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
							try(fis){
							signal = fis.read();
							}
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						} catch (IOException e1) {
							e1.printStackTrace();
						}
						
						if(signal == 254) {
							Decrypt();
						}
						if (signal == 255) {
							DecryptOFB();
						}
						signal = 0;
						break;
					}
					case 4: {
						if (signal == 0) {
							PrivateKey prikey = null;
							GenerateKeyStore();
							prikey = getPrivateKey(prikey);
							signature(prikey);
						}
						if (signal == 1) {
							PrivateKey prikey = null;
							prikey = PrivateKey_certain_place(prikey);
							signature(prikey);
						}
						signal = 0;
						break;
					}
					case 5: {
						PublicKey pubkey = null;
						pubkey = getPublicKey(pubkey);
						boolean success;
						try {
							success = confirmsig(pubkey);
							if (success == true) {
								JOptionPane.showMessageDialog(null, "验证成功");
							} else if (success == false) {
								JOptionPane.showMessageDialog(null, "验证失败");
							}
						} catch (Exception e1) {
							e1.printStackTrace();
						}
						signal = 0;
						break;
					}
					default:
						throw new IllegalArgumentException("Unexpected value: " + comboBoxFunction.getSelectedIndex());
					}
				} else if (comboBoxChooseFile.getSelectedIndex() == 1) {
					HASH_string();
				}
			}
		});
	}
	



	public void HASH_string() {
		try {
			byte[] message = textFieldFileOrText.getText().getBytes();
			MessageDigest md = MessageDigest.getInstance("SM3");
			md.update(message);
			textFieldstringHASH.setText(Hex.toHexString(md.digest()));
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}
	

	public void HASH_file() {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SM3");
			try (FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
					DigestInputStream dis = new DigestInputStream(fis, md)) {
				byte[] buffer = new byte[512];
				while (dis.read(buffer) != -1) {
				}
				textAreaHASH.setText(Hex.toHexString(md.digest()));
			}
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	public void Encrypt() {
		char[] passwd = (textFieldpasswd.getText()).toCharArray();
		try {
			Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5Padding");
			cp.init(Cipher.ENCRYPT_MODE,passwd_to_key(passwd));
			FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
			FileOutputStream fos = new FileOutputStream(textFieldFileOrText.getText() + ".sm4enc");
			int signal = 32766;
			fos.write(signal);
			CipherInputStream cis = new CipherInputStream(fis, cp);
			try (fis;fos;cis){
				cis.transferTo(fos);
			}
			JOptionPane.showMessageDialog(null,"加密成功");
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	
	public void EncryptOFB() {
		char[] passwd = (textFieldpasswd.getText()).toCharArray();
		byte[] ivalue = new byte[16];
		new SecureRandom().nextBytes(ivalue);
		IvParameterSpec iv= new IvParameterSpec(ivalue);
			try {
				Cipher cp = Cipher.getInstance("SM4/OFB/PKCS5Padding");
				cp.init(Cipher.ENCRYPT_MODE,passwd_to_key(passwd),iv);
				FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
				FileOutputStream fos = new FileOutputStream(textFieldFileOrText.getText() + ".sm4enc");
				int signal = 32767;
				fos.write(signal);
				fos.write(ivalue);
				CipherInputStream cis = new CipherInputStream(fis, cp);
				try (fis;fos;cis){
					cis.transferTo(fos);
				}
				JOptionPane.showMessageDialog(null,"加密成功");
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
	}
	
	
	public void Decrypt() {
		char[] passwd = (textFieldpasswd.getText()).toCharArray();
		try {
			Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5Padding");
			cp.init(Cipher.DECRYPT_MODE,passwd_to_key(passwd));
			FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
			FileOutputStream fos = new FileOutputStream(textFieldFileOrText.getText()+ ".sm4dec");
			int signal = fis.read();
			CipherInputStream cis = new CipherInputStream(fis, cp);
			try (fis;fos;cis){
				cis.transferTo(fos);
			}
			JOptionPane.showMessageDialog(null,"解密成功");
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	
	public void DecryptOFB() {
		char[] passwd = (textFieldpasswd.getText()).toCharArray();
		byte[] ivalue = new byte[16];
		int signal;
		try {
			Cipher cp = Cipher.getInstance("SM4/OFB/PKCS5Padding");
			FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
			FileOutputStream fos = new FileOutputStream(textFieldFileOrText.getText()+ ".sm4dec");
			signal = fis.read();
			fis.read(ivalue);
			IvParameterSpec iv = new IvParameterSpec(ivalue);
			cp.init(Cipher.DECRYPT_MODE,passwd_to_key(passwd),iv);
			CipherInputStream cis = new CipherInputStream(fis, cp);
			try (fis;fos;cis){
				cis.transferTo(fos);
			}
			JOptionPane.showMessageDialog(null,"解密成功");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	

	public static SecretKeySpec passwd_to_key(char[] passwd) throws NoSuchAlgorithmException  {
		int key_length = 16;
		byte[] byte_passwd = new String(passwd).getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		byte[] hash_passwd = md.digest(byte_passwd);
		return new SecretKeySpec(hash_passwd, 0, key_length, "SM4");
	}
	

	public boolean confirmsig(PublicKey pubkey) throws Exception {
		try (FileInputStream fis_file = new FileInputStream(textFieldFileOrText.getText());
				FileInputStream fis_sig = new FileInputStream(textFieldpasswd.getText())) {
			Signature signature = Signature.getInstance("SM3WithSM2");
			signature.initVerify(pubkey);
			byte[] buffer = new byte[1024];
			int n = 0;
			while ((n = fis_file.read(buffer)) != -1) {
				signature.update(buffer, 0, n);
			}
			byte[] sigvalue = fis_sig.readAllBytes();
			return signature.verify(sigvalue);
		} 
	}
	

	public void signature(PrivateKey prikey) {
		try {
			try (FileInputStream fis = new FileInputStream(textFieldFileOrText.getText());
					FileOutputStream fos = new FileOutputStream(textFieldFileOrText.getText() + ".sig")) {
				Signature signature = Signature.getInstance("SM3WithSM2");
				signature.initSign(prikey);
				byte[] buffer = new byte[1024];
				int n = -1;
				while ((n = fis.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				byte[] signaturValue = signature.sign();
				fos.write(signaturValue);
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	

	public PublicKey getPublicKey(PublicKey pubkey) {
		try {
			try (FileInputStream fis = new FileInputStream("./keystores/signature.cer")) {
				CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
				Certificate certificate = cf.generateCertificate(fis);
				pubkey = certificate.getPublicKey();
			}
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return pubkey;
	}
	

	public PrivateKey PrivateKey_certain_place(PrivateKey prikey) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
			String password = JOptionPane.showInputDialog(null, "请输入keystore密码");
			try (FileInputStream fis1 = new FileInputStream(textFieldpasswd.getText())) {
				char[] passwd = password.toCharArray();
				keyStore.load(fis1, passwd);
				KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd);
				KeyStore.PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore.getEntry("sm3withsm2key", protParam);
				prikey = keyEntry.getPrivateKey();
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return prikey;

	}
	

	public PrivateKey getPrivateKey(PrivateKey prikey) {
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
			try (FileInputStream fis1 = new FileInputStream("./keystores/signature.keystore")) {
				char[] passwd = "123456".toCharArray();
				keyStore.load(fis1, passwd);
				KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd);
				KeyStore.PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore.getEntry("sm3withsm2key", protParam);
				prikey = keyEntry.getPrivateKey();
			
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return prikey;
	}
	

	public Certificate selfSign(KeyPair keyPair, String subjectDN, String signatureAlgorithm) throws Exception {
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		long now = System.currentTimeMillis();
		Date startDate = new Date(now);
		X500Name dnName = new X500Name(subjectDN);
		BigInteger certSerialNumber = new BigInteger(Long.toString(now));
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1);
		Date endDate = calendar.getTime();
		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate,
				endDate, dnName, keyPair.getPublic());
		BasicConstraints basicConstraints = new BasicConstraints(true);
		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);
		return new JcaX509CertificateConverter().setProvider(bcProvider)
				.getCertificate(certBuilder.build(contentSigner));
	}
	

	public void GenerateKeyStore() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
			ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("sm2p256v1");
			keyPairGenerator.initialize(ecGenParameterSpec);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			String subjectDN = "CN=ZGX, OU=CAUC, O=CAUC, L=Dongli, ST=Tianjin, C=cn";
			String signatureAlgorithm = "SM3WithSM2";
			Certificate certificate = selfSign(keyPair, subjectDN, signatureAlgorithm);
			try (FileOutputStream fos = new FileOutputStream("./keystores/signature.cer")) {
				fos.write(certificate.getEncoded());

			}
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			char[] password = "123456".toCharArray();
			keyStore.load(null, password);
			keyStore.setKeyEntry("sm3withsm2key", keyPair.getPrivate(), password, new Certificate[] { certificate });
			try (FileOutputStream fos = new FileOutputStream("./keystores/signature.keystore")) {
				keyStore.store(fos, password);
			}
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	

}
