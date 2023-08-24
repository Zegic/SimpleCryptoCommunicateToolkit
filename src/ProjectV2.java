import java.awt.EventQueue;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
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

import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.awt.event.ActionEvent;

import javax.swing.DebugGraphics;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.Color;
import javax.swing.JScrollPane;

//imports

public class ProjectV2 extends JFrame {

	private static JPanel contentPane;
	private JTextField passwd_input_enc_text;
	private JTextField text_filePath_hash;
	private JTextField textField_sourceFIle_path_file;
	private JTextField textField_pswd_file;
	private JTextField textField_output_path_file;

	/**
	 * Launch the application.
	 */
	
	private static KeyPair rsaKeyPair;
	
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
		Main_Pane.setBackground(new Color(226, 189, 238));
		contentPane.add(Main_Pane);
		// part : main pane 
		
		
		//definition elements-------------
		
		JPanel RSA_text = new JPanel();
		RSA_text.setToolTipText("");
		Main_Pane.addTab("RSA短对话加解密", null, RSA_text, null);
		RSA_text.setLayout(null);
		
		//-----RSA-----
		JTextArea RSApubA = new JTextArea();
		RSApubA.setBounds(10, 10, 480, 99);
		RSA_text.add(RSApubA);
		//设置换行
		RSApubA.setLineWrap(true);
		RSApubA.setWrapStyleWord(true);
		JScrollPane scrollPane_input = new JScrollPane(RSApubA);
		RSA_text.add(scrollPane_input);
		scrollPane_input.setBounds(10, 10, 480, 99);

		
		JTextArea RSApubB = new JTextArea();
		RSApubB.setBounds(500, 10, 480, 99);
		RSA_text.add(RSApubB);
		RSApubB.setLineWrap(true);
		RSApubB.setWrapStyleWord(true);
		JScrollPane scrollPane = new JScrollPane(RSApubB);
		scrollPane.setBounds(500, 10, 480, 99);
		RSA_text.add(scrollPane);

		JTextArea text_input_rsa = new JTextArea();
		text_input_rsa.setBounds(10, 180, 854, 110);
		RSA_text.add(text_input_rsa);
		text_input_rsa.setLineWrap(true);
		text_input_rsa.setWrapStyleWord(true);
		
		JScrollPane scrollPane_1 = new JScrollPane(text_input_rsa);
		scrollPane_1.setBounds(10, 180, 854, 110);
		RSA_text.add(scrollPane_1);
		
		JTextArea text_output_rsa = new JTextArea();
		text_output_rsa.setBounds(10, 300, 854, 110);
		RSA_text.add(text_output_rsa);
		text_output_rsa.setLineWrap(true);
		text_output_rsa.setWrapStyleWord(true);
	
		JScrollPane scrollPane_2 = new JScrollPane(text_output_rsa);
		scrollPane_2.setBounds(10, 300, 854, 110);
		RSA_text.add(scrollPane_2);
		
		JButton btn_get_my_RSA_pub = new JButton("\u751F\u6210\u6211\u7684\u516C\u94A5");
		btn_get_my_RSA_pub.setBounds(20, 114, 269, 45);
		RSA_text.add(btn_get_my_RSA_pub);
		
		JButton btn_RSA_enc = new JButton("\u7528\u5BF9\u65B9\u516C\u94A5\u52A0\u5BC6");
		btn_RSA_enc.setBounds(687, 447, 145, 50);
		RSA_text.add(btn_RSA_enc);
		
		JButton btn_RSA_dec = new JButton("\u7528\u6211\u7684\u79C1\u94A5\u89E3\u5BC6");
		btn_RSA_dec.setBounds(842, 447, 143, 50);
		RSA_text.add(btn_RSA_dec);
		
		JTextArea debug_rsa = new JTextArea();
		debug_rsa.setBounds(21, 447, 656, 226);
		RSA_text.add(debug_rsa);
		debug_rsa.setLineWrap(true);
		debug_rsa.setWrapStyleWord(true);
		debug_rsa.setEditable(false);
		debug_rsa.setText("这里是debug窗口。\n整个软件的使用说明：待编写。\nRSA短对话加密使用说明：\n先点 生成我的公钥，然后粘贴到微信，发给你的小伙伴\n你的小伙伴生成他的公钥，然后从微信发给你\n你把你小伙伴的公钥粘贴到右上角\n然后点那个一键加密就好了，不懂的看github源码或者直接来问zegic");
		//使用说明：\n 这是zegic写的，他很懒，懒得写说明，所以自己摸索用吧。\n 实在不会用，去github上看源码，或者找zegic问\n
		JButton btn_copy_A_rsa = new JButton("\u590D\u5236");
		btn_copy_A_rsa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String text = RSApubA.getText();
				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
				StringSelection sl = new StringSelection(text);
				cb.setContents(sl, null);
				debug_rsa.append("已将你的公钥复制");
			}
		});//按钮：复制
		btn_copy_A_rsa.setBounds(354, 107, 124, 35);
		RSA_text.add(btn_copy_A_rsa);
		
		JButton btn_copy_B_rsa = new JButton("\u7C98\u8D34");
		btn_copy_B_rsa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			    Transferable contents = clipboard.getContents(null);
			    if (contents != null && contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
			        
			            String text;
						try {
							text = (String) contents.getTransferData(DataFlavor.stringFlavor);
							RSApubB.setText(text); 
							debug_rsa.append("已粘贴");
						} catch (UnsupportedFlavorException | IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
							debug_rsa.append("粘贴失败！！！\n你复制了个啥玩意？甚至不是字符串！！\n");
						}
			        //按钮：粘贴
			}}
		});
		btn_copy_B_rsa.setBounds(843, 107, 124, 34);
		RSA_text.add(btn_copy_B_rsa);
		
		JButton btn_copy_INPUT_rsa = new JButton("\u7C98\u8D34");
		btn_copy_INPUT_rsa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			    Transferable contents = clipboard.getContents(null);
			    if (contents != null && contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
			        
			            String text;
						try {
							text = (String) contents.getTransferData(DataFlavor.stringFlavor);
							text_input_rsa.setText(text); 
						} catch (UnsupportedFlavorException | IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
			        //按钮：粘贴
			}			}
		});
		btn_copy_INPUT_rsa.setBounds(874, 193, 93, 45);
		RSA_text.add(btn_copy_INPUT_rsa);
		
		JButton btn_copy_OUTPUT_rsa = new JButton("\u590D\u5236");
		btn_copy_OUTPUT_rsa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String text = text_output_rsa.getText();
				Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
				StringSelection sl = new StringSelection(text);
				cb.setContents(sl, null);
			}
		});//按钮：复制
		btn_copy_OUTPUT_rsa.setBounds(874, 332, 93, 45);
		RSA_text.add(btn_copy_OUTPUT_rsa);
		
		JButton btn_INPUT2_rsa = new JButton("\u6E05\u7A7A");
		btn_INPUT2_rsa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				text_input_rsa.setText("");
			}
		});
		btn_INPUT2_rsa.setBounds(874, 248, 93, 29);
		RSA_text.add(btn_INPUT2_rsa);
		

		JButton btn_START_RSA = new JButton("\u3010 \u4E00\u952E\u81EA\u52A8\u52A0\u89E3\u5BC6\u5E76\u590D\u5236\u7C98\u8D34 \u3011");
		btn_START_RSA.setBounds(713, 533, 242, 118);
		RSA_text.add(btn_START_RSA);

		//====RSA====
		
		
		//-----hash
		JPanel Encrypt_text = new JPanel();
		Main_Pane.addTab("对话加解密", null, Encrypt_text, null);
		Encrypt_text.setLayout(null);
		
		JPanel Encrypt_File = new JPanel();
		Encrypt_File.setBackground(new Color(243, 240, 245));
		Main_Pane.addTab("文件加解密", null, Encrypt_File, null);
		Encrypt_File.setLayout(null);
		
		JButton btn_file_path_fileenc = new JButton("\u9009\u62E9\u5F85\u52A0\u89E3\u5BC6\u6587\u4EF6");
		btn_file_path_fileenc.setBounds(10, 44, 131, 51);
		Encrypt_File.add(btn_file_path_fileenc);
		
		textField_sourceFIle_path_file = new JTextField();
		textField_sourceFIle_path_file.setBounds(151, 44, 834, 51);
		Encrypt_File.add(textField_sourceFIle_path_file);
		textField_sourceFIle_path_file.setColumns(10);
		
		textField_pswd_file = new JTextField();
		textField_pswd_file.setBounds(207, 167, 544, 51);
		Encrypt_File.add(textField_pswd_file);
		textField_pswd_file.setColumns(10);
		
		JComboBox comboBox_choose_suanfa = new JComboBox();
		comboBox_choose_suanfa.setBackground(new Color(250, 250, 250));
		comboBox_choose_suanfa.setBounds(10, 167, 187, 51);
		Encrypt_File.add(comboBox_choose_suanfa);
		
		textField_output_path_file = new JTextField();
		textField_output_path_file.setBounds(220, 296, 765, 51);
		Encrypt_File.add(textField_output_path_file);
		textField_output_path_file.setColumns(10);
		
		JButton btn_start_encrypt = new JButton("\u5F00\u59CB\u52A0\u5BC6");
		btn_start_encrypt.setBounds(299, 552, 160, 106);
		Encrypt_File.add(btn_start_encrypt);
		
		JButton btn_start_decrypt = new JButton("\u5F00\u59CB\u89E3\u5BC6");
		btn_start_decrypt.setBounds(535, 552, 160, 106);
		Encrypt_File.add(btn_start_decrypt);
		//hash====
		
		
		
		
		//----加密文件
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
		

		
		JPanel Signature = new JPanel();
		Main_Pane.addTab("数字签名", null, Signature, null);
		Signature.setLayout(null);
		
		JTextArea textArea = new JTextArea();
		textArea.setBounds(332, 267, 425, 183);
		Signature.add(textArea);
		textArea.setText("懒得做");
		//对话加解密====		
		
		//----hash
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
		comboBox_choose_hash_text_hash.setBounds(10, 151, 182, 102);
		Hash_everything.add(comboBox_choose_hash_text_hash);
		
		JTextArea text_hash_output_hash = new JTextArea();
		text_hash_output_hash.setBounds(428, 151, 557, 60);
		Hash_everything.add(text_hash_output_hash);
		
		JButton btn_choosefile_hash = new JButton("\u9009\u62E9\u6587\u4EF6");
		btn_choosefile_hash.setBounds(10, 263, 182, 52);
		Hash_everything.add(btn_choosefile_hash);
		
		comboBox_choose_hash_text_hash.setModel(new DefaultComboBoxModel<>(new String[] {"SHA-256","MD5","SM3"}));
		
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
		//======text=======
		
		//======定义部分结束。下面是按钮部分=======
		
		//------hash-------

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
		//加密文件====
		
		//标签定义区域，标签定义全放在这里========
		
		//-------text-------

		
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
		
		
		
		//======hash=======
		
		//------file-------
		btn_file_path_fileenc.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JFileChooser chooser = new JFileChooser();
				if (chooser.showOpenDialog(ProjectV2.this) == JFileChooser.APPROVE_OPTION) {
					File file = chooser.getSelectedFile();
					if (!file.isDirectory()) {
						textField_sourceFIle_path_file.setText(file.getAbsolutePath());
					}
				}
			}
		});
		comboBox_choose_suanfa.setModel(new DefaultComboBoxModel<>(new String[] {"选择加密方式,默认 AES-OFB","SM4(待开发)"}));
		
		JButton btnNewButton_1 = new JButton("\u9009\u62E9\u8F93\u51FA\u8DEF\u5F84\uFF08\u9ED8\u8BA4\u4E3A\u6E90\u8DEF\u5F84\uFF09");
		btnNewButton_1.setBounds(10, 296, 201, 51);
		Encrypt_File.add(btnNewButton_1);
		
		JButton btnNewButton_2 = new JButton("\u5BC6\u7801\u662F\u5426\u52A0\u76D0\uFF08\u9ED8\u8BA4\u52A0\u76D0\uFF0C\u5F85\u5F00\u53D1\uFF09");
		btnNewButton_2.setBounds(761, 167, 224, 51);
		Encrypt_File.add(btnNewButton_2);
		
		
		btn_start_encrypt.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				if (comboBox_choose_suanfa.getSelectedIndex() == 0) {
					//AES OFB
					//if (text_Filehash_output_hash.getText() == null ) {
						textField_output_path_file.setText(textField_sourceFIle_path_file.getText());
					//}
					encrypt_AES_file(textField_pswd_file.getText(), textField_sourceFIle_path_file.getText(), textField_output_path_file.getText());
				}
			}
		});		
		
		
		btn_start_decrypt.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				//textField_output_path_file.setText(textField_sourceFIle_path_file.getText());
				decrypt_AES_file(textField_pswd_file.getText(), textField_sourceFIle_path_file.getText(), textField_output_path_file.getText());
				
			}
		});
		//======file=======
		//-------RSA短对话
		
		//目前先不遵循这个程序的设计规范，等到功能测试ok了在搞好看点
		//先使用DHKE，然后再使用ECDH
				
		//DHKE只需两次交流：A->B , B->A
		//分成客户端和服务器的概念比较好理解
				
		//先是实现RSA
		//RSApubA RSApubB btn_start_RSA
				
		btn_get_my_RSA_pub.addActionListener(new ActionListener() {
			@Override
		public void actionPerformed(ActionEvent e) {
			// TODO Auto-generated method stub
			
			RSApubA.setText(get_my_rsa_pubkey());
			debug_rsa.setText("生成了你的公钥。快把公钥发给你的小伙伴\n");

			String text = RSApubA.getText();
			Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
			StringSelection sl = new StringSelection(text);
			cb.setContents(sl, null);
			debug_rsa.append("已经帮你把公钥复制到剪切板了\n");
		
			}
		});
	
		btn_RSA_enc.addActionListener(new ActionListener() {
			
		@Override
		public void actionPerformed(ActionEvent e) {
			// TODO Auto-generated method stub
			text_output_rsa.setText(encrypt_use_his_rsa_pubkey(RSApubB.getText(),text_input_rsa.getText()));
			debug_rsa.append("用对方的公钥加密你想给对方说的话\n");
		}
		});
	
		btn_RSA_dec.addActionListener(new ActionListener() {
		
			@Override
		public void actionPerformed(ActionEvent e) {
			// TODO Auto-generated method stub
			text_output_rsa.setText(decrypt_by_my_rsa_prikey(text_input_rsa.getText()));
		}
		});
		
		btn_START_RSA.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				debug_rsa.setText("这里是debug窗口。你按下了懒人键\n");
				debug_rsa.append("作者知道你很懒，所以帮你操作函数  \n");
				//首先判断input有没有内容
				debug_rsa.append("判断input有没有内容 \n");
				if (text_input_rsa.getText().length()!=0) {
				//如果有，判断是否是密文
					debug_rsa.append(" input有内容，判断是否是密文\n");
					if (text_input_rsa.getText().startsWith("RSAenc:")) {
						
						//是密文就将其解密，然后结束
						debug_rsa.append("是密文，将其解密 \n");
						text_output_rsa.setText(decrypt_by_my_rsa_prikey(text_input_rsa.getText()));
						debug_rsa.append("明文输出到output \n");
					}else {
						//不是密文就将其加密
						debug_rsa.append("不是密文，将其加密 \n");
						text_output_rsa.setText(encrypt_use_his_rsa_pubkey(RSApubB.getText(), text_input_rsa.getText()));
						debug_rsa.append("加密完成 \n");
						//然后复制到剪贴板
						String text = text_output_rsa.getText();
						Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
						StringSelection sl = new StringSelection(text);
						cb.setContents(sl, null);
						debug_rsa.append("输出已复制到剪贴板 \n");
						//最后想办法清空input但不导致丢失写的东西。先直接清空试试。
						//text_input_rsa.setText("");
						//debug_rsa.setText(" 清空input \n");
					}
				}else {
				//input没有内容
					debug_rsa.append("input没有内容  \n");
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				    Transferable contents = clipboard.getContents(null);
				    if (contents != null && contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
				            String text;
							try {
								text = (String) contents.getTransferData(DataFlavor.stringFlavor);
								text_input_rsa.setText(text); 
							} catch (UnsupportedFlavorException | IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}//按钮：粘贴
						}//把剪贴板内容复制到input		
				    debug_rsa.append("把剪贴板内容复制到input  \n");
				    //然后判断内容是否密文
				    debug_rsa.append("判断内容是否密文  \n");
				    if (text_input_rsa.getText().startsWith("RSAenc:")) {
				    	text_output_rsa.setText(decrypt_by_my_rsa_prikey(text_input_rsa.getText()));
				    //是密文，解密，结束
				    	debug_rsa.append("内容是密文。解密。  \n");
				    }else {
				    	debug_rsa.append("内容是明文，加密  \n");
				    	//是明文，加密，复制到剪贴板
						text_output_rsa.setText(encrypt_use_his_rsa_pubkey(RSApubB.getText(), text_input_rsa.getText()));
						String text = text_output_rsa.getText();
						Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
						StringSelection sl = new StringSelection(text);
						cb.setContents(sl, null);
						debug_rsa.append("密文已经复制到剪贴板  \n");
				}
				}
			}
		});//这个按钮实现一键加解密+复制粘贴
				
				//RSA短对话=========
		//definition ends
	}

	
//
// --------------------start functions------------------------
//
	
	//--------RSA短对话-----------
	
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
		return encodekey;
		
	}
	//生成全局的RSA本机公私密钥（全局变量定义在main）
	
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
			String output = "RSAenc:" + Base64.getEncoder().encodeToString(cipherText);
			//在这里我加入加密标志用于自动化处理。
			return output;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(contentPane, "加密内容过长！此RSA只能加密短对话\n长对话请交换密钥后去AES对话加解密\n"+e);
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "Error";
		

	}
	//用别人的公钥加密
	
	public String decrypt_by_my_rsa_prikey( String input_cipher) {
		byte[] input = Base64.getDecoder().decode(input_cipher.substring(7));
		//用这个substring来实现去除加密函数的自动化包皮
		PrivateKey prikey = rsaKeyPair.getPrivate();
		byte[] plain = null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, prikey);
			plain = cipher.doFinal(input);
			return new String(plain);
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
		return "Error";
		
		
	}
	//用自己的公钥解密
	
//整个设计思路是：通过微信互发公钥，然后各自用对方公钥加密，然后用自己的私钥解密
	
	//========RSA短对话===========
	

	
	//--------文件加密--------
	
	//我目前只做AES。毕竟国密的效率还不如AES一半
 	public void encrypt_AES_file( String password , String input_filepath , String output_filepath ) {
		char[] passwd = password.toCharArray();
		byte[] ivalue = new byte[16];
		new SecureRandom().nextBytes(ivalue);
		IvParameterSpec iv= new IvParameterSpec(ivalue);
			try {
				Cipher cp = Cipher.getInstance("AES/OFB/PKCS5Padding");
				cp.init(Cipher.ENCRYPT_MODE,passwd_to_key_AES(passwd),iv);
				FileInputStream fis = new FileInputStream(input_filepath);
				FileOutputStream fos = new FileOutputStream(output_filepath + ".zgx");
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
	//AES,OFB,加密
	
	
	public void decrypt_AES_file( String password , String input_filepath , String output_filepath ) {
		char[] passwd = password.toCharArray();
		byte[] ivalue = new byte[16];
		try {
			Cipher cp = Cipher.getInstance("AES/OFB/PKCS5Padding");
			FileInputStream fis = new FileInputStream(input_filepath);
			FileOutputStream fos = new FileOutputStream(output_filepath+ ".de");
			fis.read(ivalue);
			IvParameterSpec iv = new IvParameterSpec(ivalue);
			cp.init(Cipher.DECRYPT_MODE,passwd_to_key_AES(passwd),iv);
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
	//AES,OFB,解密
	//==========文件加密=========
	
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
