import java.awt.EventQueue;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.awt.BorderLayout;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import java.awt.Button;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.awt.event.ActionEvent;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;

//imports

public class ProjectV2 extends JFrame {

	private JPanel contentPane;
	private JTextField passwd_input_enc_text;
	private JTextField text_filePath_hash;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ProjectV2 frame = new ProjectV2();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();}}});}

	/**
	 * Create the frame.
	 */
	
	
	public ProjectV2() {
		setTitle("\u57FA\u4E8E\u7ED9\u5B9A\u4FE1\u9053\u7684\u52A0\u5BC6\u4EA4\u6D41\u88C5\u7F6E");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1024, 768);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));
		JTabbedPane Main_Pane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(Main_Pane, BorderLayout.CENTER);
		// part : main pane 
		
		
		//definition elements-------------
		
		JPanel Change_key = new JPanel();
		Change_key.setToolTipText("");
		Main_Pane.addTab("交换密钥", null, Change_key, null);
		
		JPanel Encrypt_text = new JPanel();
		Main_Pane.addTab("对话加解密", null, Encrypt_text, null);
		Encrypt_text.setLayout(null);
		
		JPanel Hash_everything = new JPanel();
		Main_Pane.addTab("计算哈希", null, Hash_everything, null);
		Hash_everything.setLayout(null);
		
		JButton btn_hash_text_start_hash = new JButton("\u8BA1\u7B97\u5B57\u7B26\u4E32\u54C8\u5E0C");
		btn_hash_text_start_hash.setBounds(202, 151, 216, 60);
		Hash_everything.add(btn_hash_text_start_hash);
		
		JTextArea text_hash_input_hash = new JTextArea();
		text_hash_input_hash.setBounds(10, 10, 975, 131);
		Hash_everything.add(text_hash_input_hash);
		
		JComboBox comboBox_choose_hash_text_hash = new JComboBox();
		comboBox_choose_hash_text_hash.setBounds(10, 151, 182, 60);
		Hash_everything.add(comboBox_choose_hash_text_hash);
		
		JTextArea text_hash_output_hash = new JTextArea();
		text_hash_output_hash.setBounds(428, 151, 557, 60);
		Hash_everything.add(text_hash_output_hash);
		
		JButton btn_choosefile_hash = new JButton("\u9009\u62E9\u6587\u4EF6");
		btn_choosefile_hash.setBounds(10, 263, 182, 52);
		Hash_everything.add(btn_choosefile_hash);
		
		text_filePath_hash = new JTextField();
		text_filePath_hash.setBounds(202, 264, 783, 52);
		Hash_everything.add(text_filePath_hash);
		text_filePath_hash.setColumns(10);
		
		JButton btn_hash_File_start_hash = new JButton("\u8BA1\u7B97\u6587\u4EF6\u54C8\u5E0C");
		btn_hash_File_start_hash.setBounds(10, 325, 182, 52);
		Hash_everything.add(btn_hash_File_start_hash);
		
		JTextArea text_Filehash_output_hash = new JTextArea();
		text_Filehash_output_hash.setBounds(202, 326, 783, 52);
		Hash_everything.add(text_Filehash_output_hash);
		
		JTabbedPane Encrpty_File = new JTabbedPane(JTabbedPane.TOP);
		Main_Pane.addTab("文件加解密", null, Encrpty_File, null);
		
		JTabbedPane Signature = new JTabbedPane(JTabbedPane.TOP);
		Main_Pane.addTab("签名与证书", null, Signature, null);
		//标签定义区域，标签定义全放在这里========
		
		//-------text-------
		passwd_input_enc_text = new JTextField();
		passwd_input_enc_text.setBounds(10, 267, 795, 51);
		Encrypt_text.add(passwd_input_enc_text);
		passwd_input_enc_text.setColumns(10);
		
		JTextArea text_input_enc_text = new JTextArea();
		text_input_enc_text.setBounds(10, 10, 975, 247);
		Encrypt_text.add(text_input_enc_text);
		
		JTextArea text_output_enc_text = new JTextArea();
		text_output_enc_text.setBounds(10, 328, 975, 354);
		Encrypt_text.add(text_output_enc_text);
		
		JButton btn_text_start = new JButton("\u5F00\u59CB\u52A0\u5BC6/\u89E3\u5BC6");
		btn_text_start.setBounds(815, 267, 170, 51);
		Encrypt_text.add(btn_text_start);
		
		btn_text_start.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				
				if(text_input_enc_text.getText().startsWith("encrypt:")) {
					String input_text = text_input_enc_text.getText();
					text_output_enc_text.setText(decrypt_text(input_text));					
				}
				else {
					String input_plain = text_input_enc_text.getText();
					text_output_enc_text.setText(encrypt_text(input_plain));
				}
			}
		});
		//======text=======
		
		
		//------hash-------
		comboBox_choose_hash_text_hash.setModel(new DefaultComboBoxModel<>(new String[] {"SHA-256","MD5","SM3"}));
		

		
		btn_hash_text_start_hash.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 0) {
					text_hash_output_hash.setText(HASH_string_SHA(text_hash_input_hash.getText()));
				}
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 1) {
					text_hash_output_hash.setText(HASH_string_MD5(text_hash_input_hash.getText()));
				}
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 2) {
					text_hash_output_hash.setText(HASH_string_SM3(text_hash_input_hash.getText()));
				}
			}
		});
			
		btn_choosefile_hash.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JFileChooser chooser = new JFileChooser();
				if (chooser.showOpenDialog(ProjectV2.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						text_filePath_hash.setText(file.getAbsolutePath());
					}
				}
			
			}
		});
		
		btn_hash_File_start_hash.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 0) {
					text_Filehash_output_hash.setText(HASH_file_SHA256(text_filePath_hash.getText()));
				}
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 1) {
					text_Filehash_output_hash.setText(HASH_file_MD5(text_filePath_hash.getText()));
				}
				if (comboBox_choose_hash_text_hash.getSelectedIndex() == 2) {
					text_Filehash_output_hash.setText(HASH_file_SM3(text_filePath_hash.getText()));
				}
			}
		});
		
		
		
		//======hash=======
		
		
		//under construction

		

	
		//definition ends
	}
	
//
// --------------------start functions------------------------
//
	
	//----手动加密的对话之函数区----
	public String encrypt_text( String input_message ){
		byte[] message = input_message.getBytes();
		//明文
		byte[] ivalue = new SecureRandom().generateSeed(16);
		IvParameterSpec iv = new IvParameterSpec(ivalue);
		try {
			SecretKeySpec key = passwd_to_key_AES(passwd_input_enc_text.getText().toCharArray());
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
			//编成base64输出
			return enc;
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
		return "Error";
	}
	//text分区函数。加密文本
	
	public String decrypt_text(String input_text) {
		byte[] tmp = null;
		try {
			tmp = Base64.getDecoder().decode(input_text.substring(8));
		} catch (Exception e) {
			JOptionPane.showMessageDialog(contentPane, "错误:密文不完整。请重新输入加密内容");
		}
		//定义一个tmp，用于装base64编码的全部内容，去掉加密标志0000后，转换成一串byte
		byte[] ivalue = Arrays.copyOf(tmp,16);
		byte[] message = Arrays.copyOfRange(tmp,16,tmp.length);
		//把tmp切好了给iv和密文
		try {
			SecretKeySpec key = passwd_to_key_AES(passwd_input_enc_text.getText().toCharArray());
			//创建key和iv
			Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(ivalue);
			cipher.init(Cipher.DECRYPT_MODE,key,iv);
			byte[] dec = cipher.doFinal(message);
			String plain = new String(dec);
			return plain;
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
		return "Error";
	}
	//text分区函数。解密文本
	
	public SecretKeySpec passwd_to_key_AES(char[] passwd) throws NoSuchAlgorithmException {
		int key_length = 16;
		String spw = new String(passwd);
		String reversed_passwd = new StringBuilder(spw).reverse().toString();
		String salt = "nmsl_NiXiang_Wo_RuanJian_De_Ren_MeiYou_MaMa_HackerReversingMySoftWareHasNoMother";
		String salt_pswd = reversed_passwd + salt;
		//把密码反转加盐
		byte[] byte_passwd = salt_pswd.getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		byte[] hash_passwd = md.digest(byte_passwd);
		return new SecretKeySpec(hash_passwd,0,key_length,"AES");
	}
	//===手动加密的对话之函数区====
	
	
	//------HASH------
	public String HASH_string_SM3( String input ) {
		try {
			byte[] message = input.getBytes();
			MessageDigest md = MessageDigest.getInstance("SM3");
			md.update(message);
			return Hex.toHexString(md.digest());
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
	//  SM3 字符串算hash值
	
	public String HASH_string_MD5( String input ) {
		try {
			byte[] message = input.getBytes();
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(message);
			return Hex.toHexString(md.digest());
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
	//MD5
	
	public String HASH_string_SHA( String input ) {
		try {
			byte[] message = input.getBytes();
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(message);
			return Hex.toHexString(md.digest());
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
	//sha256
	
	//希望：MD5，SHA256。现在先随便做几个
	
	public String HASH_file_SM3( String file_path ) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SM3");
			try (FileInputStream fis = new FileInputStream(file_path);
					DigestInputStream dis = new DigestInputStream(fis, md)) {
				byte[] buffer = new byte[512];
				while (dis.read(buffer) != -1) {
				}
				return Hex.toHexString(md.digest());
			}
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
	
	public String HASH_file_SHA256( String file_path ) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
			try (FileInputStream fis = new FileInputStream(file_path);
					DigestInputStream dis = new DigestInputStream(fis, md)) {
				byte[] buffer = new byte[512];
				while (dis.read(buffer) != -1) {
				}
				return Hex.toHexString(md.digest());
			}
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
	
	public String HASH_file_MD5( String file_path ) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
			try (FileInputStream fis = new FileInputStream(file_path);
					DigestInputStream dis = new DigestInputStream(fis, md)) {
				byte[] buffer = new byte[512];
				while (dis.read(buffer) != -1) {
				}
				return Hex.toHexString(md.digest());
			}
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return "Error";
	}
}
