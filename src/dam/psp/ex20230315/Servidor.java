package dam.psp.ex20230315;


import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {

	static KeyStore ks;
	
	public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		
	
		
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(System.getProperty("user.home")+"/Desktop/keystore.p12"), "practicas".toCharArray());
		try (ServerSocket serverSocket = new ServerSocket(9000)) {
			ExecutorService executor = Executors.newFixedThreadPool(100);
			System.out.println("Servidor ECHO escuchando en puerto 9000");
			while (true) {
				Socket socket = serverSocket.accept();
				executor.submit(new Peticion(socket));
			}
			
		}
		
	}

}
