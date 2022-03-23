using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Titanium.Web.Proxy.ProxySocket
{
    /// <summary>
    /// Implements the HTTP Tunnel protocol.
    /// </summary>
    internal sealed class HttpTunnelHandler : SocksHandler
    {
        /// <summary>Holds the count of newline characters received.</summary>
        private int _receivedNewlineChars;

        public string Token { get; set; }

        public HttpTunnelHandler(Socket server, string token) : base(server, string.Empty)
        {
            Token = token;
        }

        /// <inheritdoc />
        public override void Negotiate(string host, int port)
        {
            if (host == null)
                throw new ArgumentNullException();

            if (port <= 0 || port > 65535 || host.Length > 255)
                throw new ArgumentException();

            byte[] buffer = GetConnectBytes(host, port);
            if (Server.Send(buffer, 0, buffer.Length, SocketFlags.None) < buffer.Length)
            {
                throw new SocketException(10054);
            }

            ReadBytes(buffer, 13); // buffer is always longer than 13 bytes. Check the code in GetConnectBytes
            VerifyConnectHeader(buffer, 13);

            // Read bytes 1 by 1 until we reach "\r\n\r\n"
            int receivedNewlineChars = 0;
            while (receivedNewlineChars < 4)
            {
                int recv = Server.Receive(buffer, 0, 1, SocketFlags.None);
                if (recv == 0)
                {
                    throw new SocketException(10054);
                }

                byte b = buffer[0];
                if (b == (receivedNewlineChars % 2 == 0 ? '\r' : '\n'))
                {
                    receivedNewlineChars++;
                }
                else
                {
                    receivedNewlineChars = b == '\r' ? 1 : 0;
                }
            }
        }

        /// <inheritdoc />
        public override void Negotiate(IPEndPoint remoteEP)
        {
            Negotiate(remoteEP.Address.ToString(), remoteEP.Port);
        }

        /// <inheritdoc />
        public override IAsyncProxyResult BeginNegotiate
        (
            IPEndPoint remoteEP, HandShakeComplete callback, IPEndPoint proxyEndPoint, object state
        )
        {
            return BeginNegotiate(remoteEP.Address.ToString(), remoteEP.Port, callback, proxyEndPoint, state);
        }

        /// <inheritdoc />
        public override IAsyncProxyResult BeginNegotiate
        (
            string host, int port, HandShakeComplete callback, IPEndPoint proxyEndPoint, object state
        )
        {
            ProtocolComplete = callback;
            Buffer           = GetConnectBytes(host, port);
            Server.BeginConnect(proxyEndPoint, this.OnConnect, Server);
            AsyncResult = new IAsyncProxyResult(state);
            return AsyncResult;
        }

        /// <summary>
        /// Creates an array of bytes that has to be sent when the user wants to connect to a specific IPEndPoint.
        /// </summary>
        /// <returns>An array of bytes that has to be sent when the user wants to connect to a specific IPEndPoint.</returns>
        private byte[] GetConnectBytes(string host, int port)
        {
            var sb = new StringBuilder();

            sb.AppendLine($"CONNECT {host}:{port} HTTP/1.1");
            sb.AppendLine($"Host: {host}:{port}");

            if (!string.IsNullOrEmpty(Username))
            {
                sb.AppendLine($"Authentication: XAuth {Token}");
            }

            sb.AppendLine();
            byte[] buffer = Encoding.ASCII.GetBytes(sb.ToString());
            return buffer;
        }

        /// <summary>
        /// Verifies that proxy server successfully connected to requested host
        /// </summary>
        /// <param name="buffer">Input data array</param>
        /// <param name="length">The data count in the buffer</param>
        private void VerifyConnectHeader(byte[] buffer, int length)
        {
            string header = Encoding.ASCII.GetString(buffer, 0, length);
            if ((!header.StartsWith("HTTP/1.1 ", StringComparison.OrdinalIgnoreCase) &&
                 !header.StartsWith("HTTP/1.0 ", StringComparison.OrdinalIgnoreCase)) || !header.EndsWith(" "))
                throw new ProtocolViolationException();

            string code = header.Substring(9, 3);
            if (code != "200")
                throw new ProxyException("Invalid HTTP status. Code: " + code);
        }

        /// <summary>
        /// Called when the socket is connected to the remote server.
        /// </summary>
        /// <param name="ar">Stores state information for this asynchronous operation as well as any user-defined data.</param>
        private void OnConnect(IAsyncResult ar)
        {
            try
            {
                Server.EndConnect(ar);
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
                return;
            }

            try
            {
                Server.BeginSend
                (
                    Buffer, 0, Buffer.Length, SocketFlags.None, this.OnConnectSent, null
                );
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
            }
        }

        /// <summary>
        /// Called when the connect request bytes have been sent.
        /// </summary>
        /// <param name="ar">Stores state information for this asynchronous operation as well as any user-defined data.</param>
        private void OnConnectSent(IAsyncResult ar)
        {
            try
            {
                HandleEndSend(ar, Buffer.Length);
                Buffer   = new byte[13];
                Received = 0;
                Server.BeginReceive(Buffer, 0, 13, SocketFlags.None, this.OnConnectReceive, Server);
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
            }
        }

        /// <summary>
        /// Called when an connect reply has been received.
        /// </summary>
        /// <param name="ar">Stores state information for this asynchronous operation as well as any user-defined data.</param>
        private void OnConnectReceive(IAsyncResult ar)
        {
            try
            {
                HandleEndReceive(ar);
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
                return;
            }

            try
            {
                if (Received < 13)
                {
                    Server.BeginReceive
                    (
                        Buffer, Received, 13 - Received, SocketFlags.None, this.OnConnectReceive, Server
                    );
                }
                else
                {
                    VerifyConnectHeader(Buffer, 13);
                    ReadUntilHeadersEnd(true);
                }
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
            }
        }


        /// <summary>
        /// Reads socket buffer byte by byte until we reach "\r\n\r\n". 
        /// </summary>
        /// <param name="readFirstByte"></param>
        private void ReadUntilHeadersEnd(bool readFirstByte)
        {
            while (Server.Available > 0 && _receivedNewlineChars < 4)
            {
                if (!readFirstByte)
                    readFirstByte = false;
                else
                {
                    int recv = Server.Receive(Buffer, 0, 1, SocketFlags.None);
                    if (recv == 0)
                        throw new SocketException(10054);
                }

                if (Buffer[0] == (_receivedNewlineChars % 2 == 0 ? '\r' : '\n'))
                {
                    _receivedNewlineChars++;
                }
                else
                {
                    _receivedNewlineChars = Buffer[0] == '\r' ? 1 : 0;
                }
            }

            if (_receivedNewlineChars == 4)
            {
                OnProtocolComplete(null);
            }
            else
            {
                Server.BeginReceive
                (
                    Buffer, 0, 1, SocketFlags.None, this.OnEndHeadersReceive, Server
                );
            }
        }

        // I think we should never reach this function in practice
        // But let's define it just in case
        /// <summary>
        /// Called when additional headers have been received.
        /// </summary>
        /// <param name="ar">Stores state information for this asynchronous operation as well as any user-defined data.</param>
        private void OnEndHeadersReceive(IAsyncResult ar)
        {
            try
            {
                HandleEndReceive(ar);
                ReadUntilHeadersEnd(false);
            }
            catch (Exception e)
            {
                OnProtocolComplete(e);
            }
        }
    }
}
