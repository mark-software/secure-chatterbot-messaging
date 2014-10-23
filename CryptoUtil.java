package marks.custom.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;

/**
 * 
 * @author Mark Miller
 */
@SuppressWarnings("deprecation")
public final class CryptoUtil {
	public static final String MAC_ALGORITHM = "HmacSHA256";
	public static final String ALGORITHM = "DH";
	public static final String ENCRYPTION_ALGO = "AES/ECB/PKCS5Padding";
	
	public static final String PRIME_HEADER = "P";
	public static final String GENERATER_HEADER = "G";
	public static final String BIT_SIZE_HEADER = "L";
	public static final String PUBLIC_KEY_HEADER = "PK";
	
	public static final String NONCE_HEADER = "nonce";
	public static final String EXPIRE_HEADER = "expire";
	public static final String MAC_HEADER = "mac";
	public static final String MSG_HEADER = "msg";
	public static final String DEVICE_ID_HEADER = "device_id";
	
	public static int EXPIRE_TIME_MINUTES = 5;
	
	private static HttpClient client = new DefaultHttpClient();
	private static SecureRandom random = new SecureRandom();

	/**
	 * @author Mark Miller
	 * 
	 * @return - the generated Diffie–Hellman parameters g, p, and l
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidParameterSpecException
	 */
	public static DHParameterSpec generateDhParameters() throws NoSuchAlgorithmException, InvalidParameterSpecException {
		// Create the parameter generator for a 1024-bit DH key pair
		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(ALGORITHM);
		paramGen.init(1024);

		AlgorithmParameters params = paramGen.generateParameters();		

		return params.getParameterSpec(DHParameterSpec.class);
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @Note Step 1 in DH (client) key exchange protocol. We are sending 
	 * the prime, generator, bit size, and public key.
	 * @param step1Url (%1$s...%2$s)
	 * @param dhSpec
	 * @return - the JSON response from the server which will include the server's 
	 * public key. It needs to be parsed. 
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	public static String sendDhParamsWithPKToServer(String step1Url, DHParameterSpec dhSpec, PublicKey publicKey, String uniqueDeviceId) throws MalformedURLException, IOException {
		//here we could use string.format... or ya that's
		Header[] headers = buildStep1Headers(dhSpec, publicKey, uniqueDeviceId);
		
		HttpResponse response = getHttp(headers, step1Url);
		
		//return the body... which will be parsed
		return convertStreamToString(response.getEntity().getContent());
	}
	
	public static String requestDhParamsFromServer(String setupUrl, String deviceId) throws IllegalStateException, IOException {
		Header header = new BasicHeader(DEVICE_ID_HEADER, deviceId);
		
		HttpResponse response = getHttp(new Header[]{header}, setupUrl);
		return convertStreamToString(response.getEntity().getContent());
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param dhSpec
	 * @return - Public/Private key pair
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static KeyPair generateKeyPair(DHParameterSpec dhSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		keyGen.initialize(dhSpec);

		return keyGen.generateKeyPair();
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @return - Public/Private key pair
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidParameterSpecException
	 */
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
		return generateKeyPair(generateDhParameters());
	}
	
	/**  
	 * @author Mark Miller
	 * 
	 * Step 2 in DH (client) key exchange protocol
	 * @param url
	 * @param myPublicKey
	 * @return - the JSON response from the server which will include the server's 
	 * public key. It needs to be parsed. <br />(Update: nothing useful to parse here.)
	 * @throws IOException
	 */
	public static String sendPublicKeyToServer(String url, PublicKey publicKey, String deviceId) throws IOException {
		
		String base64Pk = byteArrayToBase64String(publicKey.getEncoded());
		
		Header[] headers = new BasicHeader[2];
		headers[0] = new BasicHeader(PUBLIC_KEY_HEADER, base64Pk);
		headers[1] = new BasicHeader(DEVICE_ID_HEADER, deviceId);
		
		HttpResponse response = getHttp(headers, url);
		
		//return the body... which will be parsed
		return convertStreamToString(response.getEntity().getContent());
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param myPrivateKey - your own private key
	 * @param base64OtherPublicKey - base64 encoded public key string from other party NOT URL encoded
	 * @return - Two secret keys. key[0] is the AES key. key[1] is the HMAC key.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 */
	public static SecretKey[] calculateSecretKeys(PrivateKey myPrivateKey, String base64OtherPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		//first decode into byte array
		byte[] otherPartyPkBytes = Base64.decodeBase64(base64OtherPublicKey.getBytes());
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(otherPartyPkBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		
		PublicKey publicKey  = keyFactory.generatePublic(x509KeySpec);
		
		//generate secret key
		KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM);
		ka.init(myPrivateKey);
		
		ka.doPhase(publicKey, true);
		
		SecretKey combinedSecretKey = ka.generateSecret("AES");
		SecretKey aesKey = new SecretKeySpec(combinedSecretKey.getEncoded(), 0, combinedSecretKey.getEncoded().length/2, "AES");
		
		byte[] macKeyBytes = new byte[combinedSecretKey.getEncoded().length/2];
		System.arraycopy(combinedSecretKey.getEncoded(), combinedSecretKey.getEncoded().length/2, macKeyBytes, 0, macKeyBytes.length);		
		SecretKey macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");
	
		
		SecretKey[] secretKeys = {aesKey, macKey};
		
		return secretKeys;
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param myPrivateKey - your own private key
	 * @param base64OtherPublicKey - base64 encoded public key string from other party NOT URL encoded
	 * @return - Two secret keys. key[0] is the AES key. key[1] is the HMAC key.
	 * @throws GeneralSecurityException 
	 */
	public static SecretKey[] calculateSecretKeys(String myBase64PrivateKey, String base64OtherPublicKey) throws GeneralSecurityException {
		//first decode into byte array
		byte[] otherPartyPkBytes = Base64.decodeBase64(base64OtherPublicKey.getBytes());
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(otherPartyPkBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		
		PublicKey publicKey  = keyFactory.generatePublic(x509KeySpec);
		
		//generate secret key
		KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM);
		ka.init(loadPrivateKey(myBase64PrivateKey));
		
		ka.doPhase(publicKey, true);
		
		SecretKey combinedSecretKey = ka.generateSecret("AES");
		SecretKey aesKey = new SecretKeySpec(combinedSecretKey.getEncoded(), 0, combinedSecretKey.getEncoded().length/2, "AES");
		
		byte[] macKeyBytes = new byte[combinedSecretKey.getEncoded().length/2];
		System.arraycopy(combinedSecretKey.getEncoded(), combinedSecretKey.getEncoded().length/2, macKeyBytes, 0, macKeyBytes.length);		
		SecretKey macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");
	
		
		SecretKey[] secretKeys = {aesKey, macKey};
		
		return secretKeys;
	}
	
    public static String convertStreamToString(InputStream is) {
    	BufferedReader reader = new BufferedReader(new InputStreamReader(is));    	
    	String line, response="";
    	
    	try {
			while((line = reader.readLine()) != null)
				response += line;
		} catch (IOException e) {
			return null;
		}
    	return response;
    }
	
    public static HttpResponse getHttp(final Header[] headers, String url) {
    	HttpResponse response = null;
    	HttpGet httpGet = new HttpGet(url);

    	try {
    		if(headers != null)
    			httpGet.setHeaders(headers);
    		
    		response = client.execute(httpGet);
    		//TODO close client
    	}
    	catch(Exception e) {
    		return null;
    	}
    	
    	return response;
    }
    
    public static HttpResponse postHttp(final Header[] headers, final String url) {
    	HttpResponse response = null;    	
    	HttpPost httpPost = new HttpPost(url);
    	
    	try {
    		//add headers..
    		if(headers != null)
    			httpPost.setHeaders(headers);
    		
    		response = client.execute(httpPost);
    	}
    	catch(Exception e) {
    		return null; //or exception...
    	}
    	
    	return response;
    }
    
    /**
     * @author Mark Miller
     * 
     * @param dhSpec
     * @param publicKey
     * @return - the headers which contain info for setting up step 1 of the Diffie–Hellman key exchange protocol
     * @throws UnsupportedEncodingException
     */
    public static Header[] buildStep1Headers(DHParameterSpec dhSpec, PublicKey publicKey, String uniqueDeviceId) throws UnsupportedEncodingException {
    	BigInteger p = dhSpec.getP();
		BigInteger g = dhSpec.getG();
		int l = dhSpec.getL();
		
		String base64p = new String(Base64.encodeBase64(p.toByteArray()));
		String base64g = new String(Base64.encodeBase64(g.toByteArray()));
		String base64l = new String(Base64.encodeBase64(BigInteger.valueOf(l).toByteArray()));
		String base64PK = new String(Base64.encodeBase64(publicKey.getEncoded()));
		
		Header[] headers = new BasicHeader[5];
		headers[0] = new BasicHeader(PRIME_HEADER, base64p);
		headers[1] = new BasicHeader(GENERATER_HEADER, base64g);
		headers[2] = new BasicHeader(BIT_SIZE_HEADER, base64l);
		headers[3] = new BasicHeader(PUBLIC_KEY_HEADER, base64PK);
		headers[4] = new BasicHeader(DEVICE_ID_HEADER, uniqueDeviceId);
		
				    	
    	return headers;
    }
    
    public static String newNonce() {
    	return new String(Base64.encodeBase64(BigInteger.valueOf(random.nextLong()).toByteArray()));
    }
    
    /**
     * @author Mark Miller
     * 
     * Sat, 09 Aug 2014 00:30:18 GMT
     * @return - A date X minutes from creation time     * 
     */
	public static String newExpire() {
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MINUTE, EXPIRE_TIME_MINUTES);
		Date date = c.getTime();

		//Date date = new Date(new Date().getTime() + (EXPIRE_TIME_MINUTES * ONE_MINUTE_IN_MILLIS));
		
		SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
		sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
		String d = sdf.format(date);

		return d;
	}

	/**
	 * @author Mark Miller
	 * 
	 * @param key - the secret key
	 * @param msg - the message            
	 * @return - the base64 encoded mac
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 */
	public static String mac(SecretKey key, String msg) throws NoSuchAlgorithmException, IllegalStateException,
														UnsupportedEncodingException, InvalidKeyException {
		
		Mac sha256_hmac = Mac.getInstance(MAC_ALGORITHM);
		sha256_hmac.init(key);
		byte[] m = sha256_hmac.doFinal(msg.getBytes("UTF8"));

		return new String(Base64.encodeBase64(m));
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param key - the secret key
	 * @param msg - the message            
	 * @return - the base64 encoded mac
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 */
	public static String mac(String base64Key, String msg) throws NoSuchAlgorithmException, IllegalStateException,
														UnsupportedEncodingException, InvalidKeyException {
		
		Mac sha256_hmac = Mac.getInstance(MAC_ALGORITHM);
		byte[] keyBytes = base64StringToByteArray(base64Key);
		
		sha256_hmac.init(new SecretKeySpec(keyBytes, "AES"));
		byte[] m = sha256_hmac.doFinal(msg.getBytes("UTF8"));

		return new String(Base64.encodeBase64(m));
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param secretKey
	 * @param str - String to encrypt
	 * @return - a base64 encoded string
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static String encrypt(SecretKey secretKey, String str) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher ecipher = Cipher.getInstance(ENCRYPTION_ALGO);		

		ecipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encodedBytes =ecipher.doFinal(str.getBytes("UTF8"));

		return new String(Base64.encodeBase64(encodedBytes));
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param secretKey
	 * @param str - String to encrypt
	 * @return - a base64 encoded string
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException 
	 */
	public static String encrypt(String base64SecretKey, String str) throws UnsupportedEncodingException, GeneralSecurityException {
		Cipher ecipher = Cipher.getInstance(ENCRYPTION_ALGO);		

		byte[] keyBytes = base64StringToByteArray(base64SecretKey);
		ecipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
		byte[] encodedBytes =ecipher.doFinal(str.getBytes("UTF8"));

		return new String(Base64.encodeBase64(encodedBytes));
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param secretKey
	 * @param str - Base64 encoded string to decrypt
	 * @return - decrypted string
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException 
	 */
	public static String decrypt(SecretKey secretKey, String str) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher dcipher = Cipher.getInstance(ENCRYPTION_ALGO);
		dcipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] bytesToDecrypt = Base64.decodeBase64(str.getBytes());

		//decrypt the bytes..
		byte[] utf8Bytes = dcipher.doFinal(bytesToDecrypt);

		return new String(utf8Bytes, "UTF8");		
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param secretKey
	 * @param str - Base64 encoded string to decrypt
	 * @return - decrypted string
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException 
	 */
	public static String decrypt(String base64SecretKey, String str) throws UnsupportedEncodingException, GeneralSecurityException {
		Cipher dcipher = Cipher.getInstance(ENCRYPTION_ALGO);
		
		byte[] keyBytes = base64StringToByteArray(base64SecretKey);
		dcipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
		byte[] bytesToDecrypt = Base64.decodeBase64(str.getBytes());

		//decrypt the bytes..
		byte[] utf8Bytes = dcipher.doFinal(bytesToDecrypt);

		return new String(utf8Bytes, "UTF8");		
	}
	
	public static String byteArrayToBase64String(byte[] bytes) {
		return new String(Base64.encodeBase64(bytes));
	}
	
	public static byte[] base64StringToByteArray(String str) {
		return Base64.decodeBase64(str.getBytes());
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param base64p
	 * @param base64g
	 * @param base64l
	 * @return - Diffie–Hellman parameters p, g, l
	 */
	public static DHParameterSpec buildDHParamSpec(String base64p, String base64g, String base64l) {
		//p and g must be BigIntegers... 
		//l is an int
		BigInteger p = new BigInteger(Base64.decodeBase64(base64p.getBytes()));
		BigInteger g = new BigInteger(Base64.decodeBase64(base64g.getBytes()));
		int l = new BigInteger(Base64.decodeBase64(base64l.getBytes())).intValue();
		
		return new DHParameterSpec(p, g, l);
	}
	
	/**
	 * @author Mark Miller
	 * 
	 * @param msg
	 * @param secretKey
	 * @return - The headers
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
    public static Header[] buildSendMsgHeaders(String msg, SecretKey secretKey, String uniqueDeviceId) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException  {
    	
    	String expire = newExpire().trim();
    	String nonce = newNonce().trim();
    	//now encrypt the message
    	msg = encrypt(secretKey, msg.trim());
    	
		Header[] headers = new BasicHeader[5];
		headers[0] = new BasicHeader(MSG_HEADER, msg);
		headers[1] = new BasicHeader(NONCE_HEADER, nonce);
		headers[2] = new BasicHeader(EXPIRE_HEADER, expire);
		headers[3] = new BasicHeader(DEVICE_ID_HEADER, uniqueDeviceId);
		String strToMac = msg+nonce+expire+uniqueDeviceId;
		
		headers[4] = new BasicHeader(MAC_HEADER, mac(secretKey, strToMac));
				    	
    	return headers;
    }

    /**
     * @author Mark Miller
     * 
     * @param msg - the input message for the bot
     * @param url - the URL (should include the ?personality=...)
     * @param secretKey
     * @return - JSON which will need to be parsed! The message will be encrypted
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalStateException
     * @throws IOException
     */
    public static String getSecureServerMessageResponse(String msg, String url, SecretKey secretKey, String uniqueDeviceId) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IllegalStateException, IOException {
    	Header[] headers = buildSendMsgHeaders(msg, secretKey, uniqueDeviceId);
    	HttpResponse response = getHttp(headers, url);
    	
		//return the body... which will be parsed
		return convertStreamToString(response.getEntity().getContent());
    }
    
    /**
     * @author Mark Miller
     * 
     * @param encryptedMsg
     * @param nonce
     * @param expire
     * @param expectedMac
     * @param secretKey
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IllegalStateException
     * @throws UnsupportedEncodingException
     */
    public static boolean isMacValid(String encryptedMsg, String nonce, String expire, String uniqueDeviceId, String expectedMac, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {
    	String strToMac = encryptedMsg+nonce+expire+uniqueDeviceId;
    	String actualMac = mac(secretKey, strToMac);

    	return strToMac.equals(actualMac);
    }
    
	//Might have to change to x509...
	//Credit: http://stackoverflow.com/a/9755391/1159930
	public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
	    byte[] clear = CryptoUtil.base64StringToByteArray(key64);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
	    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
	    PrivateKey priv = fact.generatePrivate(keySpec);
	    Arrays.fill(clear, (byte) 0);
	    return priv;
	}
	
	//Credit: http://stackoverflow.com/a/9755391/1159930
	public static PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
	    byte[] data = CryptoUtil.base64StringToByteArray(stored);
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
	    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
	    return fact.generatePublic(spec);
	}
}
