package internetcomputing.ai.project;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

//singleton wrapper
public final class EMF {
	private static final EntityManagerFactory emfInstance = Persistence
			.createEntityManagerFactory("transactions-optional");
	
	private EMF() {}
	
	public static EntityManagerFactory getInstance() {
		return emfInstance;
	}
}
