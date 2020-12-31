/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.IOException;
import java.security.cert.*;
import java.io.*;
import java.util.Base64;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;


public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost;
    public static int sessionPort;
    private SessionEncrypter session_encrypter;
    private SessionDecrypter session_decrypter; 

    /* Security parameters key/iv should also go here. Fill in! */

    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 

    public SessionEncrypter getSessionEncrypter()
    {
        return session_encrypter;
    }

    public SessionDecrypter getSessionDecrypter()
    {
        return session_decrypter;
    }

     // ADDED AN EXTRA ARGUMENT (arguments)
    public ClientHandshake(Socket handshakeSocket, Arguments arguments) throws IOException, Exception {

        // Get the CA certificate and user certificate. Verify them.
        X509Certificate ca_cert = VerifyCertificate.getCertificate(arguments.get("cacert"));
        X509Certificate user_cert = VerifyCertificate.getCertificate(arguments.get("usercert"));
        boolean valid_user_cert = VerifyCertificate.verify(ca_cert, user_cert, true);
        if(!valid_user_cert)
        {
            System.out.println("Handshake failed.");
            handshakeSocket.close();
            System.exit(0);
        }

        // Encode the user certificate.
        String u_cert_string = Base64.getEncoder().encodeToString((user_cert).getEncoded());

        // Create ClientHello message.
        HandshakeMessage clienthello = new HandshakeMessage();
        clienthello.putParameter("MessageType", "ClientHello");
        clienthello.putParameter("Certificate", u_cert_string);
        System.out.println("Client sending ClientHello.");
        clienthello.send(handshakeSocket);


        // Wait for ServerHello message.
        HandshakeMessage serverhello = new HandshakeMessage();
        serverhello.recv(handshakeSocket);
        if(!serverhello.getParameter("MessageType").equals("ServerHello"))
        {
            // Handshake failed
            System.out.println("Handshake failed.");
            handshakeSocket.close();
            System.exit(0);
        }
        else
        {
            // Check server's certificate
            System.out.println("Client received ServerHello.");
            String s_cert_string = serverhello.getParameter("Certificate");
            byte [] Cert = java.util.Base64.getDecoder().decode(s_cert_string);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(Cert);
            X509Certificate server_cert = (X509Certificate)factory.generateCertificate(is);
            boolean res = VerifyCertificate.verify(ca_cert, server_cert, false);
            if (res == false)
            {
                // fail
                System.out.println("Handshake failed.");
                handshakeSocket.close();
                System.exit(0);
            }
            else
            {
                // Create Forward message.
                HandshakeMessage forward = new HandshakeMessage();
                forward.putParameter("MessageType", "Forward");
                forward.putParameter("TargetHost", arguments.get("targethost"));
                forward.putParameter("TargetPort", arguments.get("targetport").toString());
                System.out.println("Client sending Forward.");
                forward.send(handshakeSocket);


                // Wait for Session message.
                HandshakeMessage serversession = new HandshakeMessage();
                serversession.recv(handshakeSocket);
                if(!serversession.getParameter("MessageType").equals("Session"))
                {
                    // Handshake failed
                    System.out.println("Handshake failed.");
                    handshakeSocket.close();
                    System.exit(0);
                }
                else
                {
                    // Get the Host and Port
                    System.out.println("Client received Session.");
                    sessionHost = serversession.getParameter("SessionHost");
                    sessionPort = Integer.parseInt(serversession.getParameter("SessionPort"));

                    //Get encrypted IV and Key
                    String IVcipher_string = serversession.getParameter("SessionIV");
                    String Keycipher_string = serversession.getParameter("SessionKey");

                    // Decode
                    byte[] IVcipher_text = Base64.getDecoder().decode(IVcipher_string);
                    byte[] Keycipher_text = Base64.getDecoder().decode(Keycipher_string);

                    // Decrypt with private key of user
                    PrivateKey pk = HandshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
                    byte[] IV = HandshakeCrypto.decrypt(IVcipher_text, pk);
                    byte[] Session_Key = HandshakeCrypto.decrypt(Keycipher_text, pk);

                    session_encrypter = new SessionEncrypter(Session_Key, IV);
                    session_decrypter = new SessionDecrypter(Session_Key, IV);

                    System.out.println("Client completing handshake.");
                    // close socket
                    handshakeSocket.close();
                }

            }
        }
    }
}
