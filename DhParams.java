package marks.custom.crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class DhParams {
	public String base64p;
	public String base64g;
	public String base64l;
	public String base64PublicKey;
	public String base64PrivateKey;
	
	public DhParams(DHParameterSpec dhSpec, PublicKey publicKey, PrivateKey privateKey) {
		BigInteger p = dhSpec.getP();
		BigInteger g = dhSpec.getG();
		int l = dhSpec.getL();
		
		base64p = Base64.encodeBase64String(p.toByteArray());
		base64g = Base64.encodeBase64String(g.toByteArray());
		base64l = Base64.encodeBase64String(BigInteger.valueOf(l).toByteArray());
		base64PublicKey = Base64.encodeBase64String(publicKey.getEncoded());
		base64PrivateKey = Base64.encodeBase64String(privateKey.getEncoded());
	}
}
