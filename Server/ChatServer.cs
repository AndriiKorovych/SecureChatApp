using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

class ChatServer
{
    private const int Port = 5000;
    private readonly List<SslStream> clients = new List<SslStream>();

    public static void Main()
    {
        new ChatServer().Start();
    }

    public void Start()
    {
        var certificate = new X509Certificate2("server.pfx", "password");
        TcpListener listener = new TcpListener(IPAddress.Any, Port);
        listener.Start();
        Console.WriteLine($"Сервер чату запущено на порту {Port}.");

        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("Клієнт підключився.");
            ThreadPool.QueueUserWorkItem(HandleClient, new Tuple<TcpClient, X509Certificate2>(client, certificate));
        }
    }

    private void HandleClient(object state)
    {
        var (client, certificate) = (Tuple<TcpClient, X509Certificate2>)state;
        using SslStream sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate);
        sslStream.AuthenticateAsServer(certificate, clientCertificateRequired: true, System.Security.Authentication.SslProtocols.Tls12, checkCertificateRevocation: true);

        lock (clients)
        {
            clients.Add(sslStream);
        }

        try
        {
            while (true)
            {
                byte[] buffer = new byte[1024];
                int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"Клієнт написав: {message}");
                BroadcastMessage(message, sslStream);
            }
        }
        finally
        {
            lock (clients)
            {
                clients.Remove(sslStream);
            }
        }
    }

    private void BroadcastMessage(string message, SslStream sender)
    {
        lock (clients)
        {
            foreach (var client in clients)
            {
                if (client != sender)
                {
                    byte[] data = Encoding.UTF8.GetBytes(message);
                    client.Write(data);
                }
            }
        }
    }

    private bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine($"Сертифікат клієнта валідний: {certificate.Subject}");
            return true;
        }

        Console.WriteLine($"Сертифікат клієнта недійсний: {sslPolicyErrors}");
        return false;
    }
}
