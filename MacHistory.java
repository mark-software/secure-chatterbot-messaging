package internetcomputing.ai.project;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class MacHistory {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private String mac;

	public String getMac() {
		return mac;
	}

	public void setMac(String mac) {
		this.mac = mac;
	}	
}
