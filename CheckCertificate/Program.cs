using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Net;

class TestX509Chain
{
    static void Main(string[] args)
    {
        //Do webrequest to get info on secure site

        Console.Write("Enter web site name:  ");
        string WebSitename = Console.ReadLine();


        try
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(WebSitename);

            //  HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://mail.outlook.com");

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            response.Close();

            //retrieve the ssl cert and assign it to an X509Certificate object
            X509Certificate cert = request.ServicePoint.Certificate;

            //convert the X509Certificate to an X509Certificate2 object by passing it into the constructor
            X509Certificate2 cert2 = new X509Certificate2(cert);

            string cn = cert2.GetIssuerName();
            string cedate = cert2.GetExpirationDateString();
            string cpub = cert2.GetPublicKeyString();

            //display the cert dialog box
            X509Certificate2UI.DisplayCertificate(cert2);

            // Output chain information of the selected certificate.

            X509Chain ch = new X509Chain();
            ch.Build(cert2);
            Console.WriteLine("Chain Information");
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);
            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);


                X509Certificate2 certTest = new X509Certificate2(element.Certificate);


                // byte[] rawdata = certTest;

                // Console.WriteLine("Content Type: {0}{1}", certTest.GetCertContentType(rawdata), Environment.NewLine);
                Console.WriteLine("Friendly Name: {0}{1}", certTest.FriendlyName, Environment.NewLine);


                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
        }

        catch (Exception e)

        // catch (WebException e)
        {
            Console.WriteLine("Error:  ");
            Console.WriteLine (e);
            return;
        }

        finally
        {

            Console.WriteLine("all good");

        }





    }
}
