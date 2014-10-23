package internetcomputing.ai.project;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;

import marks.custom.crypto.CryptoUtil;
import marks.custom.crypto.DhParams;

import com.google.api.server.spi.config.Api;
import com.google.api.server.spi.config.ApiMethod;
import com.google.api.server.spi.config.ApiMethod.HttpMethod;
import com.google.api.server.spi.config.Named;
import com.google.appengine.api.datastore.Text;
import com.google.code.chatterbotapi.ChatterBot;
import com.google.code.chatterbotapi.ChatterBotFactory;
import com.google.code.chatterbotapi.ChatterBotSession;
import com.google.code.chatterbotapi.ChatterBotType;

/**
 * @author Mark Miller
 * 
 * <br /><br />
 * 
 * This is a basic web app/service that will respond to appropriately formatted
 * GET requests. <br /> It uses Chatter Bot to return a response. <br />
 * Responses are available in three personalities. See documentation below.
 * <br /><br />
 * Security has been added so that the API is not abused. <br />
 * 
 * A database may be added at a later time so we can keep track of users.
 * <br />
 * Notes:<br /> 
 * Be sure to close the EMF instance after using it. Use a finally block<br />
 * Measures have NOT been taken to maintain perfect secrecy. E.g., an attacker 
 * could use response time or invalid input to predict output and potentially
 * break the encryption. In a real implementation it is an absolute must that this is done!
 * 
 */
@Api(name = "ai" )
public class AiEndpoint {

	public class AiMessage {
		public String msg;
		public String context;
		public String P, G, L, PK;
		public String extra;

	}

	@Deprecated
	@ApiMethod(name = "ai.message", path = "talk_unsecure", httpMethod = HttpMethod.GET)
	public AiMessage getText(@Named("text") String msg, @Named("personality") String personality) {
		AiMessage aim = new AiMessage();

		//Remove percent encoding
		msg = msg.replace("%20", " ");

		aim.msg = getResponse(msg, personality);
		aim.context = "Internet Computing project";
		return aim;
	}

	/**
	 * This is used to get a secure response from the web service
	 * @param req - the request which includes the headers
	 * @param personality
	 * @return - the response cipher-text
	 */
	@ApiMethod(name = "ai.secure_message", path = "talk_secure", httpMethod = HttpMethod.GET)
	public AiMessage getSecureText(HttpServletRequest req, @Named("personality") String personality) {
		AiMessage aim = new AiMessage();
		String id = req.getHeader(Constants.DEVICE_ID_HEADER);
		String msg = req.getHeader(Constants.MSG_HEADER);
		String expire = req.getHeader(Constants.EXPIRE_HEADER);
		String nonce = req.getHeader(Constants.NONCE_HEADER);
		String mac = req.getHeader(Constants.MAC_HEADER).trim();

		if(macIsValid(mac, id, id, msg, expire, nonce) && expireIsValid(expire)) {
			//then decrypt msg and reply with encrypted text
			try {
				saveMac(mac);
				
				Device d = getDevice(id);
				String m1PlainText = CryptoUtil.decrypt(d.getBase64AesKey(), msg);
				String m2Response = getResponse(m1PlainText, personality);
				m2Response = CryptoUtil.encrypt(d.getBase64AesKey(), m2Response);
				m2Response+=":"+CryptoUtil.mac(d.getBase64HmacKey(), m2Response); //ciphertext:mac
				aim.msg = m2Response;
			}
			catch(Exception e) {
				aim.msg = "Access denied!";
				//aim.extra = e.getMessage();
			}
		}		
		else {
			aim.msg = "Access denied!";
		}
		
		aim.context = "Internet Computing project";
		return aim;
	}

	/**
	 * Step 1 for Diffie–Hellman key exchange
	 * @param req
	 * @return - the parameters needed to set up the Diffie–Hellman key exchange protocol
	 */
	@ApiMethod(name = "DHstep1", path = "setup_params", httpMethod = HttpMethod.GET)
	public AiMessage setupDhParams(HttpServletRequest req) {
		AiMessage aim = new AiMessage();
		try {
			String deviceId = req.getHeader(Constants.DEVICE_ID_HEADER);

			//generate p, g, l
			DHParameterSpec dhSpec = CryptoUtil.generateDhParameters();

			//generate public/private keys
			KeyPair keyPair = CryptoUtil.generateKeyPair(dhSpec);
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			DhParams params = new DhParams(dhSpec, publicKey, privateKey);

			//set return params
			aim.P = params.base64p;
			aim.G = params.base64g;
			aim.L = params.base64l;
			aim.PK = params.base64PublicKey;

			EntityManager em = null;
			try {				
				em = EMF.getInstance().createEntityManager();
				Device d = new Device();
				d.setDeviceId(deviceId);
				String pk = CryptoUtil.byteArrayToBase64String(privateKey.getEncoded());
				d.setBase64PrivateKey(new Text(pk)); 

				if(!doesDeviceExist(deviceId)) 
					em.persist(d);
				else 
					updateDevice(d);
				//updating would happen if the device's cache got wiped				
			}
			finally {
				em.close();
			}
		}
		catch(Exception e) {
			aim.msg = "Access denied!";
			aim.P = null;
			aim.G = null;
			aim.L = null;
			aim.PK = null;
		}

		aim.context = "Internet Computing project";
		return aim;
	}

	/**
	 * Step 2 for Diffie–Hellman key exchange. Here the client sends its public key
	 * to the server to complete the two step process.
	 * @param req
	 * @return - nothing useful
	 */
	@ApiMethod(name = "DHstep2", path = "send_pk", httpMethod = HttpMethod.GET)
	public AiMessage setupDhPk(HttpServletRequest req) {
		AiMessage aim = new AiMessage();
		try {
			String base64PublicKey = req.getHeader(Constants.PUBLIC_KEY_HEADER);
			String deviceId = req.getHeader(Constants.DEVICE_ID_HEADER);
			Device d = getDevice(deviceId);

			SecretKey[] secretKeys = CryptoUtil.calculateSecretKeys(d.getBase64PrivateKey(), base64PublicKey);
			String aesKey = CryptoUtil.byteArrayToBase64String(secretKeys[0].getEncoded());
			String hmacKey = CryptoUtil.byteArrayToBase64String(secretKeys[1].getEncoded());
			d.setBase64AesKey(aesKey);
			d.setBase64HmacKey(hmacKey);
			updateDevice(d);
		}
		catch(Exception e) {
			aim.msg = "Access denied!";
		}

		aim.context = "Internet Computing project";
		return aim;
	}

	/**
	 * 
	 * @param inputMsg - The input message that the robot responds to
	 * @param personality - May be CLEVERBOT or JABBERWACKY
	 * @return - The response from the bot or "Error"
	 */
	private String getResponse(String inputMsg, String personality) {
		ChatterBotType personalityType = null;
		try {
			if (personality != null) 
				personalityType = ChatterBotType.valueOf(personality.toUpperCase());
			else
				throw new Exception();
		} 
		catch (Exception e) {
			personalityType = ChatterBotType.CLEVERBOT;
		}

		try {
			ChatterBot bot = new ChatterBotFactory().create(personalityType);
			ChatterBotSession botSession = bot.createSession();

			return botSession.think(inputMsg);

		} catch (Exception e) {
			return "Error";
		}
	}


	@SuppressWarnings("unchecked")
	private boolean doesDeviceExist(String id) {
		EntityManager em = null;
		try {
			boolean found = false;
			em = EMF.getInstance().createEntityManager();
			Query q = em.createQuery("select d from Device d where d.deviceId = '"+id+"'");
			List<Device> l = q.getResultList();

			for(Device d: l)
				if(d.getDeviceId().equals(id)) found = true;

			return found;
		}
		finally {
			em.close();
		}
	}

	@SuppressWarnings("unchecked")
	private Device getDevice(String id) {
		EntityManager em = null;
		try {
			em = EMF.getInstance().createEntityManager();
			Query q = em.createQuery("select d from Device d where d.deviceId = '"+id+"'");
			List<Device> l = q.getResultList();
			for(Device d: l)
				if(d.getDeviceId().equals(id)) return d;
		}
		finally {
			em.close();
		}
		return null;
	}

	private void updateDevice(Device d) {
		EntityManager em = null;
		try {
			em = EMF.getInstance().createEntityManager();

			Device currentDevice = getDevice(d.getDeviceId());
			if(d.getBase64AesKey() != null)
				currentDevice.setBase64AesKey(d.getBase64AesKey());
			if(d.getBase64HmacKey() != null)
				currentDevice.setBase64HmacKey(d.getBase64HmacKey());
			if(d.getBase64PrivateKey() != null)
				currentDevice.setBase64PrivateKey(new Text(d.getBase64PrivateKey()));

			em.persist(currentDevice);	
		}
		finally {
			em.close();
		}
	}
	
	/**
	 * Mechanism to prevent replay attacks
	 * @param mac
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private boolean macDoesExist(String mac) {
		EntityManager em = null;
		try {
			boolean found = false;
			em = EMF.getInstance().createEntityManager();
			Query q = em.createQuery("select m from MacHistory m where m.mac = '"+mac+"'");
			List<MacHistory> l = q.getResultList();

			for(MacHistory mh: l)
				if(mh.getMac().equals(mac)) found = true;

			return found;
		}
		finally {
			em.close();
		}
	}

	private void saveMac(String mac) {
		EntityManager em = null;
		try {				
			em = EMF.getInstance().createEntityManager();
			MacHistory mh = new MacHistory();
			mh.setMac(mac);
						
			em.persist(mh);			
		}
		finally {
			em.close();
		}
	}
	
	//	private void deleteDevice(String id) {
	//		EntityManager em = null;
	//		try {
	//			em = EMF.getInstance().createEntityManager();			
	//			em.remove(getDevice(id));
	//		}
	//		finally {
	//			em.close();
	//		}
	//	}

	private boolean macIsValid(String expectedMac, String deviceId, String... s) {
		try {			
			if(macDoesExist(expectedMac)) return false;
			
			String mac = "";
			Device d = getDevice(deviceId);
			for(String str: s)
				mac+=":"+str.trim();

			mac+=":";

			String actualMac = CryptoUtil.mac(d.getBase64HmacKey(), mac);
			return actualMac.equals(expectedMac);
		} catch (Exception e) {
			return false;
		} 
	}

	private boolean expireIsValid(String expire) {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
			Date givenDate = sdf.parse(expire);
			Date now = new Date();
			if(givenDate.before(now))
				return false;
			
			return true;
			
		} catch (ParseException e) {
			return false;
		}
	}

}
