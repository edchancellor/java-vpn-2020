/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.cert.*;
import java.io.*;
import java.util.Base64;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost;
    public static int targetPort;
    private SessionEncrypter session_encrypter;
    private SessionDecrypter session_decrypter; 

    /* Security parameters key/iv should also go here. Fill in! */

    public SessionEncrypter getSessionEncrypter()
    {
        return session_encrypter;
    }

    public SessionDecrypter getSessionDecrypter()
    {
        return session_decrypter;
    }

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket, Arguments arguments) throws IOException, Exception {

        // Get the CA certificate and user certificate. Verify them.
        X509Certificate ca_cert = VerifyCertificate.getCertificate(arguments.get("cacert"));
        X509Certificate user_cert = VerifyCertificate.getCertificate(arguments.get("usercert"));
        boolean valid_user_cert = VerifyCertificate.verify(ca_cert, user_cert, false);
        if(!valid_user_cert)
        {
            handshakeSocket.close();
            throw new Exception();
        }

        // Wait for ClientHello message.
        HandshakeMessage clienthello = new HandshakeMessage();
        clienthello.recv(handshakeSocket);
        if(!clienthello.getParameter("MessageType").equals("ClientHello"))
        {
            // Handshake failed
            handshakeSocket.close();
            throw new Exception();
        }
        else
        {            
            // Decode the client certificate, and verify it.
            System.out.println("Server received ClientHello.");
            String u_cert_string = clienthello.getParameter("Certificate");
            byte [] Cert = java.util.Base64.getDecoder().decode(u_cert_string);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(Cert);
            X509Certificate client_cert = (X509Certificate)factory.generateCertificate(is);
            boolean res = VerifyCertificate.verify(ca_cert, client_cert, true);
            if (res == false)
            {
                // Handshake failed
                handshakeSocket.close();
                throw new Exception();
            }
            else
            {
                // Create new ServerHello message.
                HandshakeMessage serverhello = new HandshakeMessage();
                String s_cert_string = Base64.getEncoder().encodeToString((user_cert).getEncoded());
                serverhello.putParameter("MessageType", "ServerHello");
                serverhello.putParameter("Certificate", s_cert_string);
                System.out.println("Server sending ServerHello.");
                serverhello.send(handshakeSocket);


                // Wait for Forward message.
                HandshakeMessage forward = new HandshakeMessage();
                forward.recv(handshakeSocket);
                if(!forward.getParameter("MessageType").equals("Forward"))
                {
                    // Handshake failed
                    handshakeSocket.close();
                    throw new Exception();
                }
                else
                {
                    // Record the target host and target port.
                    System.out.println("Server received Forward.");
                    targetHost = forward.getParameter("TargetHost");
                    targetPort = Integer.parseInt(forward.getParameter("TargetPort"));
                    
                    // Set up a new socket.
                    sessionSocket = new ServerSocket(12345);
                    sessionHost = sessionSocket.getInetAddress().getHostName();
                    sessionPort = sessionSocket.getLocalPort();

                    // create an IV and Key
                    session_encrypter = new SessionEncrypter(128);
                    byte[] IV = session_encrypter.getIVBytes();
                    byte[] Session_Key = session_encrypter.getKeyBytes();
                    session_decrypter = new SessionDecrypter(Session_Key, IV);

                    // Get the client's public key
                    PublicKey client_key = client_cert.getPublicKey();

                    // Encrypt the IV and Key with this public key.
                    byte[] IVcipher_text = HandshakeCrypto.encrypt(IV, client_key);
                    String IVcipher_string = Base64.getEncoder().encodeToString(IVcipher_text);
                    
                    byte[] Keycipher_text = HandshakeCrypto.encrypt(Session_Key, client_key);
                    String Keycipher_string = Base64.getEncoder().encodeToString(Keycipher_text);

                    // Create new Session message.
                    HandshakeMessage Session = new HandshakeMessage();
                    Session.putParameter("MessageType", "Session");
                    Session.putParameter("SessionKey", Keycipher_string);
                    Session.putParameter("SessionIV", IVcipher_string);
                    Session.putParameter("SessionHost", sessionHost);
                    Session.putParameter("SessionPort", Integer.toString(sessionPort));
                    System.out.println("Server sending Session.");
                    Session.send(handshakeSocket);
                    System.out.println("Server completing handshake.");
                    // Close connection
                }
            }
        }
    }
}
