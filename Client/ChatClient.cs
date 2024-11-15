using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

class ChatClient
{
    private const string ServerAddress = "127.0.0.1";
    private const int Port = 5000;

    public static void Main()
    {
        new ChatClient().Run();
    }

    public void Run()
    {
        using TcpClient client = new TcpClient(ServerAddress, Port);
        using SslStream sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate);

        var clientCertificate = new X509Certificate2("client_cert.pem");
        sslStream.AuthenticateAsClient(ServerAddress, new X509CertificateCollection { clientCertificate }, System.Security.Authentication.SslProtocols.Tls12, checkCertificateRevocation: true);

        Console.WriteLine("Підключено до сервера чату.");

        Thread readThread = new Thread(() => ReadMessages(sslStream));
        readThread.Start();

        while (true)
        {
            string message = Console.ReadLine();
            byte[] data = Encoding.UTF8.GetBytes(message);
            sslStream.Write(data);
        }
    }

    private void ReadMessages(SslStream sslStream)
    {
        while (true)
        {
            byte[] buffer = new byte[1024];
            int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
            string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            Console.WriteLine($"Чат: {message}");
        }
    }

    private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine($"Сертифікат сервера валідний: {certificate.Subject}");
            return true;
        }

        Console.WriteLine($"Сертифікат сервера недійсний: {sslPolicyErrors}");
        return false;
    }
}
