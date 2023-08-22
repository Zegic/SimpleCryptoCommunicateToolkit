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
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import java.awt.Color;
import javax.swing.JTextArea;



public class EndProject extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextField input_passwd;
	public JTextArea main_input_text;
	public JTextArea main_output_text;
	protected int signal = 0;

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					EndProject frame = new EndProject();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public EndProject() {


		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 805, 500);
		contentPane = new JPanel();
		contentPane.setBackground(new Color(230, 230, 255));
		contentPane.setForeground(new Color(0, 0, 0));
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		

		JComboBox comboBoxChooseFile = new JComboBox();
		comboBoxChooseFile.setBounds(10, 10, 139, 60);
		contentPane.add(comboBoxChooseFile);
		

		JComboBox comboBoxFunction = new JComboBox();
		comboBoxFunction.setBounds(10, 242, 139, 60);
		contentPane.add(comboBoxFunction);
		

		JButton btnAction = new JButton("开始");
		btnAction.setBounds(530, 393, 120, 60);
		contentPane.add(btnAction);
		

		JButton btnExit = new JButton("退出");
		btnExit.setBounds(660, 393, 120, 60);
		contentPane.add(btnExit);
		

		JButton btnChooseFile = new JButton("...");
		btnChooseFile.setBounds(98, 80, 51, 50);
		contentPane.add(btnChooseFile);
		

		JButton btnSig = new JButton("...");
		btnSig.setBounds(93, 312, 56, 50);
		contentPane.add(btnSig);
		

		input_passwd = new JTextField();
		input_passwd.setBounds(159, 168, 621, 60);
		contentPane.add(input_passwd);
		input_passwd.setColumns(10);
		

		comboBoxFunction.setVisible(false);
		btnSig.setVisible(false);
		btnChooseFile.setVisible(false);

		
		
		main_input_text = new JTextArea();
		main_input_text.setBounds(159, 10, 622, 147);
		//contentPane.add(main_input_text);
		main_input_text.setLineWrap(true);
		main_input_text.setWrapStyleWord(true);
		
		JScrollPane scrollPane_input = new JScrollPane(main_input_text);
		contentPane.add(scrollPane_input);
		scrollPane_input.setBounds(159, 10, 622, 147);
		//滚动input
		
		main_output_text = new JTextArea();
		main_output_text.setBounds(159, 242, 622, 141);
		//contentPane.add(main_output_text);
		main_output_text.setText("在上面文本框输入要加密的内容，中间输入密码，解密明文在此显示");
		main_output_text.setEditable(false);
		main_output_text.setLineWrap(true);
		main_output_text.setWrapStyleWord(true);
		
		JScrollPane scrollPane_output = new JScrollPane(main_output_text);
		contentPane.add(scrollPane_output);
		scrollPane_output.setBounds(159, 242, 622, 141);
		contentPane.add(scrollPane_output);
		
		
		btnChooseFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				if (chooser.showOpenDialog(EndProject.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						main_input_text.setText(file.getAbsolutePath());
					}
				}
			}
		});
		

		comboBoxChooseFile.setModel(new DefaultComboBoxModel(new String[] {"对话加解密" ,"文件加解密","交换密钥" }));
		

		comboBoxChooseFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (comboBoxChooseFile.getSelectedIndex() == 0) {
					comboBoxFunction.setVisible(false);
					main_output_text.setVisible(true);
					input_passwd.setVisible(true);
					btnChooseFile.setVisible(false);
					btnSig.setVisible(false);
					main_output_text.setText("在上面文本框输入要加密的内容，中间输入密码，解密明文在此显示");
				}
				if (comboBoxChooseFile.getSelectedIndex() == 1) {
					comboBoxFunction.setVisible(true);
					main_output_text.setVisible(true);
					input_passwd.setVisible(true);
					btnChooseFile.setVisible(true);
					main_output_text.setText("选择文件并在中间框内输入密码");
				}
				if(comboBoxChooseFile.getSelectedIndex()==2) {
					comboBoxFunction.setVisible(false);
					main_output_text.setVisible(true);
					input_passwd.setVisible(true);
					btnChooseFile.setVisible(false);
					btnSig.setVisible(false);
					main_output_text.setText("密码或者密钥交换码将在此显示");
					main_input_text.setText("在此处输入密钥交换码(可选)");
					input_passwd.setText("在此处输入你自己的密码");
				}
				
			}
		});
		

		comboBoxFunction.setModel(new DefaultComboBoxModel<>(new String[] { "计算HASH值", "文件加密(ECB)", "文件加密(OFB)","文件解密", "文件数字签名", "数字签名验证" }));
		


		comboBoxFunction.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				switch (comboBoxFunction.getSelectedIndex()) {
				case 0: {
					input_passwd.setVisible(false);
					input_passwd.setText("(HASH值将在此显示)");
					btnSig.setVisible(false);
					break;
				}
				case 1: {
					input_passwd.setVisible(true);
					input_passwd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 2:{
					input_passwd.setVisible(true);
					input_passwd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 3: {
					input_passwd.setVisible(true);
					input_passwd.setText("(在此输入口令)");
					btnSig.setVisible(false);
					break;
				}
				case 4: {
					input_passwd.setVisible(true);
					btnSig.setVisible(true);
					input_passwd.setText("(选择密钥库文件，缺省则使用默认路径)");
					break;
				}
				case 5: {
					input_passwd.setVisible(true);
					btnSig.setVisible(true);
					input_passwd.setText("(选择签名文件)");
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
				if (chooser.showOpenDialog(EndProject.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						input_passwd.setText(file.getAbsolutePath());
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
				if (comboBoxChooseFile.getSelectedIndex() == 1) {
					switch (comboBoxFunction.getSelectedIndex()) {
					case 0: {
						HASH_file();
						break;
					}
					case 1: {
						encrypt_file();
						break;
					}
					case 2:{
						encrypt_OFB_file();
						break;
					}
					case 3: {
						int signal = 0;
						try {
							FileInputStream fis = new FileInputStream(main_input_text.getText());
							try(fis){
							signal = fis.read();
							}
						} catch (FileNotFoundException e1) {
							e1.printStackTrace();
						} catch (IOException e1) {
							e1.printStackTrace();
						}
						
						if(signal == 254) {
							decrypt_file();
						}
						if (signal == 255) {
							decrypt_OFB_file();
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
				} else if (comboBoxChooseFile.getSelectedIndex() == 0) {
					if(main_input_text.getText().startsWith("encrypt:")) {
						decrypt_text();
					}
					else {
						encrypt_text();
					}
				}
				else if(comboBoxChooseFile.getSelectedIndex()==2) {
					if(main_input_text.getText().startsWith("code:")) {
						xchange_code();
					}
					else {
						try {
							make_code();
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
					}
					//想法是只需发送很少的几次字符段就可以实现密钥交换
				}
			}
		});
	}
	
	public void xchange_code() {
		
	}
	//希望使用ECDH交换
	public void make_code() throws Exception{
		// 生成ECDH密钥对
		/*
		KeyPairGenerator keyPairgen = KeyPairGenerator.getInstance("DH");
		keyPairgen.initialize(2048);
        */
	}
	//之前AES一直是128位。我想给他改成256，但是需要改很多函数
	//这里的ECDH希望使用512位，以匹配256位AES，为将来升级。但是好像默认256
	

	public void encrypt_text(){
		byte[] message = (main_input_text.getText()).getBytes();
		//明文
		byte[] ivalue = new SecureRandom().generateSeed(16);
		IvParameterSpec iv = new IvParameterSpec(ivalue);
		try {
			SecretKeySpec key = passwd_to_key_AES(input_passwd.getText().toCharArray());
			//创建key和iv
			Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE,key,iv);
			//下面是把明文加密后，和iv值粘在一起，放入临时数组
			byte[] ciphtxt = cipher.doFinal(message);
			byte[] tmp = new byte[16+ciphtxt.length];
			System.arraycopy(ivalue,0,tmp,0,16);
			System.arraycopy(ciphtxt,0,tmp,16,ciphtxt.length);
			// 把明文加密后，和iv值粘在一起，放入临时数组
			String enc = "encrypt:"+Base64.getEncoder().encodeToString(tmp);
			main_output_text.setText(enc);
			//编成base64输出
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	//解密文本，AES，从main input输入密文
	
	public void decrypt_text() {
		byte[] tmp = null;
		try {
			tmp = Base64.getDecoder().decode(main_input_text.getText().substring(8));
		} catch (Exception e) {
			JOptionPane.showMessageDialog(contentPane, "错误:密文不完整。请重新输入加密内容");
		}
		//定义一个tmp，用于装base64编码的全部内容，去掉加密标志0000后，转换成一串byte
		byte[] ivalue = Arrays.copyOf(tmp,16);
		byte[] message = Arrays.copyOfRange(tmp,16,tmp.length);
		//把tmp切好了给iv和密文
		try {
			SecretKeySpec key = passwd_to_key_AES(input_passwd.getText().toCharArray());
			//创建key和iv
			Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(ivalue);
			cipher.init(Cipher.DECRYPT_MODE,key,iv);
			byte[] dec = cipher.doFinal(message);
			String plain = new String(dec);
			main_output_text.setText(plain);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			JOptionPane.showMessageDialog(contentPane, "错误:密文不完整。请重新输入加密内容");
		} catch (BadPaddingException e) {
			e.printStackTrace();
			JOptionPane.showMessageDialog(contentPane, "密码错误，请重新输入密码");
		}
	}
	//AES加密文本编码base64
	
	public void HASH_string() {
		try {
			byte[] message = main_input_text.getText().getBytes();
			MessageDigest md = MessageDigest.getInstance("SM3");
			md.update(message);
			main_output_text.setText(Hex.toHexString(md.digest()));
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}
	//字符串算hash值，大作业的遗留函数，目前没什么用，或许以后会有用

	public void HASH_file() {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SM3");
			try (FileInputStream fis = new FileInputStream(main_input_text.getText());
					DigestInputStream dis = new DigestInputStream(fis, md)) {
				byte[] buffer = new byte[512];
				while (dis.read(buffer) != -1) {
				}
				main_output_text.setText(Hex.toHexString(md.digest()));
			}
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	
	public void encrypt_file() {
		char[] passwd = (input_passwd.getText()).toCharArray();
		try {
			Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5Padding");
			cp.init(Cipher.ENCRYPT_MODE,passwd_to_key(passwd));
			FileInputStream fis = new FileInputStream(main_input_text.getText());
			FileOutputStream fos = new FileOutputStream(main_input_text.getText() + ".en");
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
	
	
	public void encrypt_OFB_file() {
		char[] passwd = (input_passwd.getText()).toCharArray();
		byte[] ivalue = new byte[16];
		new SecureRandom().nextBytes(ivalue);
		IvParameterSpec iv= new IvParameterSpec(ivalue);
			try {
				Cipher cp = Cipher.getInstance("SM4/OFB/PKCS5Padding");
				cp.init(Cipher.ENCRYPT_MODE,passwd_to_key(passwd),iv);
				FileInputStream fis = new FileInputStream(main_input_text.getText());
				FileOutputStream fos = new FileOutputStream(main_input_text.getText() + ".en");
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
	
	
	public void decrypt_file() {
		char[] passwd = (input_passwd.getText()).toCharArray();
		try {
			Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5Padding");
			cp.init(Cipher.DECRYPT_MODE,passwd_to_key(passwd));
			FileInputStream fis = new FileInputStream(main_input_text.getText());
			FileOutputStream fos = new FileOutputStream(main_input_text.getText()+ ".de");
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
	
	
	public void decrypt_OFB_file() {
		char[] passwd = (input_passwd.getText()).toCharArray();
		byte[] ivalue = new byte[16];
		int signal;
		try {
			Cipher cp = Cipher.getInstance("SM4/OFB/PKCS5Padding");
			FileInputStream fis = new FileInputStream(main_input_text.getText());
			FileOutputStream fos = new FileOutputStream(main_input_text.getText()+ ".de");
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
	//SM4，口令封装密钥
	
	public SecretKeySpec passwd_to_key_AES(char[] passwd) throws NoSuchAlgorithmException {
		int key_length = 16;
		String spw = new String(passwd);
		String reversed_passwd = new StringBuilder(spw).reverse().toString();
		String salt = "nmsl_NiXiang_Wo_RuanJian_De_Ren_MeiYou_MaMa_HackReversingMySoftWareHasNoMother";
		String salt_pswd = reversed_passwd + salt;
		//把密码反转加盐
		byte[] byte_passwd = salt_pswd.getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		byte[] hash_passwd = md.digest(byte_passwd);
		return new SecretKeySpec(hash_passwd,0,key_length,"AES");
	}
	//AES，口令封装密钥
	/*	public SecretKeySpec passwd_to_key_AES(char[] passwd) throws NoSuchAlgorithmException {
		int key_length = 16;
		String spw = new String(passwd);
		String reversed_passwd = new StringBuilder(spw).reverse().toString();
		String salt = "salt";
		String salt_pswd = reversed_passwd + salt;
		byte[] byte_passwd = salt_pswd.getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		byte[] hash_passwd = md.digest(byte_passwd);
		return new SecretKeySpec(hash_passwd,0,key_length,"AES");
	}*/
/*	public SecretKeySpec passwd_to_key_AES(char[] passwd) throws NoSuchAlgorithmException {
		//现在想加盐了
		int key_length = 16;
		
		byte[] byte_passwd = new String(passwd).getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		byte[] hash_passwd = md.digest(byte_passwd);
		System.out.println(hash_passwd);
		return new SecretKeySpec(hash_passwd,0,key_length,"AES");
		
	}*/
	/*public SecretKeySpec passwd_to_key_AES(char[] passwd) throws NoSuchAlgorithmException {
		//现在想加盐了
		int key_length = 16;
		System.out.println(passwd);
		String addsalt = passwd.toString();
		System.out.println(addsalt);
		String salt = new StringBuffer(addsalt).reverse().toString();
		System.out.println(salt);
		//salt= salt+"nmsl_NiXiang_Wo_RuanJian_De_Ren_MeiYou_MaMa_HackReversingMySoftWareHasNoMother";
		System.out.println(salt);
		byte[] byte_passwd = new String(salt).getBytes();
		System.out.println(salt);
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		System.out.println(md);
		byte[] hash_passwd = md.digest(byte_passwd);
		System.out.println(md);
		return new SecretKeySpec(hash_passwd,0,key_length,"AES");
		
	}*/
	
//下面的全是签名用函数。我已经把他们忘光了，同时密码学答辩的时候删掉了所有注释，但是忘记补回来了
	public boolean confirmsig(PublicKey pubkey) throws Exception {
		try (FileInputStream fis_file = new FileInputStream(main_input_text.getText());
				FileInputStream fis_sig = new FileInputStream(input_passwd.getText())) {
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
			try (FileInputStream fis = new FileInputStream(main_input_text.getText());
					FileOutputStream fos = new FileOutputStream(main_input_text.getText() + ".sig")) {
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
			try (FileInputStream fis1 = new FileInputStream(input_passwd.getText())) {
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
