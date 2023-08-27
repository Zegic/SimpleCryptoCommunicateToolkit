import org.bouncycastle.util.encoders.Hex;

public class text2 {
	public static void main(String[] args) {
		System.out.println(Hex.toHexString(fun()));
	}
	
	public static byte[] fun() {
		//String hex = "e11010";
		// a b c d e f 1234567890
		
		//fault
		return Hex.decode("e4404fa014");
	}
}
