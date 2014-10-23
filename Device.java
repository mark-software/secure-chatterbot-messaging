package internetcomputing.ai.project;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import com.google.appengine.api.datastore.Text;

@Entity
public class Device {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private String deviceId;

	
	private String base64AesKey;
	private String base64HmacKey;
	private Text base64PrivateKey;

	
	public String getBase64AesKey() {
		return base64AesKey;
	}
	public void setBase64AesKey(String base64AesKey) {
		this.base64AesKey = base64AesKey;
	}
	public String getBase64HmacKey() {
		return base64HmacKey;
	}
	public void setBase64HmacKey(String base64HmacKey) {
		this.base64HmacKey = base64HmacKey;
	}
	public String getBase64PrivateKey() {
		return base64PrivateKey.getValue();
	}
	public void setBase64PrivateKey(Text base64PrivateKey) {
		this.base64PrivateKey = base64PrivateKey;
	}
	public String getDeviceId() {
		return deviceId;
	}
	public void setDeviceId(String deviceId) {
		this.deviceId = deviceId;
	}
}
