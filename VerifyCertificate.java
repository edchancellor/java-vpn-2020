import java.security.cert.*;
import java.io.*;


public class VerifyCertificate{

    public static X509Certificate getCertificate(String cert) throws Exception
    {
        FileInputStream stream1 = new FileInputStream(cert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert_ = (X509Certificate)factory.generateCertificate(stream1);
        return cert_;
    }
    
    
    public static boolean verify(X509Certificate cert_CA, X509Certificate cert_user, boolean Am_I_Client) throws FileNotFoundException, IOException, Exception 
    {
        /*
        0 Print the DN for the CA (one line)
        1 Print the DN for the user (one line)
        2 Check the DN of CA and user
        3 Verify the CA certificate
        4 Verify the user certificate
        5 Print "Pass" if check 3 and 4 are successful
        6 Print "Fail" if any of them fails, followed by an explanatory comment of how the verification failed
        */

        try
        {
            String cert_CA_String = cert_CA.getSubjectDN().getName().toString();
            String cert_user_String = cert_user.getSubjectDN().getName().toString();

            String[] sub_CA = cert_CA_String.split(",");
            String[] sub_user = cert_user_String.split(",");

            System.out.println(cert_CA_String);            
            System.out.println(cert_user_String);

            boolean verified_CA = true;
            boolean valid_CA = true;
            boolean verified_user = true;
            boolean valid_user = true;
            boolean correct_CA = true;
            boolean correct_user = true;
            boolean correct_CA_email = false;
            boolean correct_user_email = false;

            // 2
            if(cert_CA_String.indexOf("CN=ca-pf.ik2206.kth.se") == -1)
            {
                correct_CA = false;
            }

            if(Am_I_Client == true)
            {
                if(cert_user_String.indexOf("CN=client-pf.ik2206.kth.se") == -1)
                {
                    correct_user = false;
                }
            }
            else
            {
                if(cert_user_String.indexOf("CN=server-pf.ik2206.kth.se") == -1)
                {
                    correct_user = false;
                }
            }

            for(int i = 0; i < sub_CA.length; i ++)
            {
                if(sub_CA[i].indexOf("EMAILADDRESS=") != -1)
                {
                    if(sub_CA[i].indexOf("@kth.se") != -1)
                    {
                        correct_CA_email = true;
                        break;
                    }
                }
            }

            for(int i = 0; i < sub_user.length; i ++)
            {
                if(sub_user[i].indexOf("EMAILADDRESS=") != -1)
                {
                    if(sub_user[i].indexOf("@kth.se") != -1)
                    {
                        correct_user_email = true;
                        break;
                    }
                }
            }


            //3
            try
            {
                // Verifies it was signed correctly
                cert_CA.verify(cert_CA.getPublicKey());
            }
            catch(Exception e)
            {
                verified_CA = false;
            }

            try
            {
                // Checks if valid
                cert_CA.checkValidity();
            }
            catch(Exception e)
            {
                valid_CA = false;
            }

            //4
            try
            {
                // Verifies it was signed correctly
                cert_user.verify(cert_CA.getPublicKey());
            }
            catch(Exception e)
            {
                verified_user = false;
            }

            try
            {
                // Checks if valid
                cert_user.checkValidity();
            }
            catch(Exception e)
            {
                valid_user = false;
            }

            //5
            if(verified_CA && verified_user && valid_CA && valid_user && correct_CA && correct_user && correct_CA_email && correct_user_email)
            {
                System.out.println("Pass");
                return true;
            }
            else
            {
                System.out.println("Fail");
                return false;
            }

        }
        catch (Exception e)
        {
            System.out.println("Fail");
            return false;
        }
    }       
        
        

        

}