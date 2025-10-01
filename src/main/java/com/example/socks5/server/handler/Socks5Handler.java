package com.example.socks5.server.handler;

import com.example.socks5.auth.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class Socks5Handler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(Socks5Handler.class);

    private final Socket clientSocket;
    private final com.example.socks5.auth.Authenticator authenticator;
    private static final int BUFFER_SIZE = 8192;
    private static final int SOCKET_TIMEOUT = 30000; // 30 seconds

    private InputStream clientIn;
    private OutputStream clientOut;
    private final String clientInfo;

    public Socks5Handler(Socket clientSocket, Authenticator authenticator) {
        this.clientSocket = clientSocket;
        this.authenticator = authenticator;
        this.clientInfo = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
    }

    @Override
    public void run() {
        logger.info("Handling connection from: {}", clientInfo);

        try {
            // Set socket timeout
            clientSocket.setSoTimeout(SOCKET_TIMEOUT);

            clientIn = clientSocket.getInputStream();
            clientOut = clientSocket.getOutputStream();

            // SOCKS5握手
            if (!handleHandshake()) {
                return;
            }

            // 强制认证
            if (!handleAuthentication()) {
                return;
            }

            // 处理客户端请求
            handleRequest();

        } catch (SocketTimeoutException e) {
            logger.warn("Socket timeout for client: {}", clientInfo);
        } catch (IOException e) {
            logger.error("Error handling client {}: {}", clientInfo, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error handling client {}: {}", clientInfo, e.getMessage(),e);
        } finally {
            closeQuietly(clientSocket);
            logger.info("Connection closed: {}", clientInfo);
        }
    }

    private boolean handleHandshake() throws IOException {
        // 读取客户端握手请求
        int version = clientIn.read();
        if (version == -1) {
            logger.debug("Client disconnected during handshake");
            return false;
        }

        if (version != 0x05) {
            logger.warn("Unsupported SOCKS version from {}: {}", clientInfo, version);
            return false;
        }

        int methodCount = clientIn.read();
        if (methodCount == -1) {
            logger.debug("Client disconnected during handshake");
            return false;
        }

        byte[] methods = clientIn.readNBytes(methodCount);
        if (methods.length != methodCount) {
            logger.warn("Incomplete handshake data from {}", clientInfo);
            return false;
        }

        // 检查支持的认证方法 - 只支持用户名/密码认证
        boolean supportsUserPass = false;

        for (byte method : methods) {
            if (method == 0x02) { // USERNAME/PASSWORD
                supportsUserPass = true;
                break;
            }
        }

        // 选择认证方法 - 强制使用用户名/密码认证
        byte selectedMethod = supportsUserPass ? (byte) 0x02 : (byte) 0xFF;

        // 发送握手响应
        clientOut.write(new byte[]{0x05, selectedMethod});
        clientOut.flush();

        if (selectedMethod == (byte) 0xFF) {
            logger.warn("Client {} doesn't support username/password authentication", clientInfo);
            return false;
        }

        logger.debug("Handshake completed for client: {}", clientInfo);
        return true;
    }

    private boolean handleAuthentication() throws IOException {
        // 读取认证版本
        int authVersion = clientIn.read();
        if (authVersion == -1) {
            logger.debug("Client {} disconnected during authentication",clientInfo);
            return false;
        }

        if (authVersion != 0x01) {
            logger.warn("Unsupported authentication version from {}: {}", clientInfo, authVersion);
            return false;
        }

        // 读取用户名
        int usernameLen = clientIn.read();
        if (usernameLen == -1) {
            logger.debug("Client {} disconnected during authentication",clientInfo);
            return false;
        }

        byte[] usernameBytes = clientIn.readNBytes(usernameLen);
        if (usernameBytes.length != usernameLen) {
            logger.warn("Incomplete username data from {}",clientInfo);
            return false;
        }
        String username = new String(usernameBytes, StandardCharsets.UTF_8);

        // 读取密码
        int passwordLen = clientIn.read();
        if (passwordLen == -1) {
            logger.debug("Client {} disconnected during authentication",clientInfo);
            return false;
        }

        byte[] passwordBytes = clientIn.readNBytes(passwordLen);
        if (passwordBytes.length != passwordLen) {
            logger.warn("Incomplete password data from {}", clientInfo);
            return false;
        }
        String password = new String(passwordBytes, StandardCharsets.UTF_8);

        // 验证凭据
        boolean authenticated = authenticator.authenticate(username, password);

        // 发送认证响应
        byte status = authenticated ? (byte) 0x00 : (byte) 0x01;
        clientOut.write(new byte[]{0x01, status});
        clientOut.flush();

        return authenticated;
    }

    private void handleRequest() throws IOException {
        // 读取请求头
        byte[] header = clientIn.readNBytes(4); // version, command, reserved, address type
        if (header.length != 4) {
            throw new IOException("Incomplete request header");
        }

        if (header[0] != 0x05) {
            throw new IOException("Invalid SOCKS version in request: " + header[0]);
        }

        byte command = header[1];
        byte addressType = header[3];

        if (command != 0x01) { // 只支持CONNECT命令
            logger.warn("Unsupported command from {}: {}", clientInfo, command);
            sendErrorResponse((byte)0x07); // Command not supported
            return;
        }

        // 解析目标地址
        String targetHost;
        int targetPort;

        switch (addressType) {
            case 0x01: // IPv4
                byte[] ipv4 = clientIn.readNBytes(4);
                if (ipv4.length != 4) {
                    throw new IOException("Incomplete IPv4 address");
                }
                targetHost = InetAddress.getByAddress(ipv4).getHostAddress();
                break;
            case 0x03: // Domain name
                int domainLen = clientIn.read();
                if (domainLen == -1) {
                    throw new IOException("Incomplete domain length");
                }
                byte[] domainBytes = clientIn.readNBytes(domainLen);
                if (domainBytes.length != domainLen) {
                    throw new IOException("Incomplete domain name");
                }
                targetHost = new String(domainBytes, StandardCharsets.UTF_8);
                break;
            case 0x04: // IPv6
                byte[] ipv6 = clientIn.readNBytes(16);
                if (ipv6.length != 16) {
                    throw new IOException("Incomplete IPv6 address");
                }
                targetHost = InetAddress.getByAddress(ipv6).getHostAddress();
                break;
            default:
                logger.warn("Unsupported address type from {}: {}", clientInfo, addressType);
                sendErrorResponse((byte)0x08); // Address type not supported
                return;
        }

        // 读取端口
        byte[] portBytes = clientIn.readNBytes(2);
        if (portBytes.length != 2) {
            throw new IOException("Incomplete port data");
        }
        targetPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);

        if (targetPort == 0 || targetPort > 65535) {
            throw new IOException("Invalid port number: " + targetPort);
        }

        logger.info("Client {} connecting to: {}:{}",clientInfo, targetHost, targetPort);

        // 连接到目标服务器
        try (Socket targetSocket = new Socket()) {
            // Set connection timeout
            targetSocket.connect(new InetSocketAddress(targetHost, targetPort), 10000);

            // Remove timeout for data transfer
            clientSocket.setSoTimeout(0);

            // 发送成功响应
            sendSuccessResponse(targetSocket.getLocalAddress(), targetSocket.getLocalPort());

            // 开始数据转发
            startTunneling(targetSocket, targetHost, targetPort);

        } catch (IOException e) {
            logger.error("Failed to connect to target {}:{} from client {}: {}",
                        targetHost, targetPort, clientInfo, e.getMessage());
            sendErrorResponse((byte)0x05); // Connection refused
        }
    }

    private void sendSuccessResponse(InetAddress bindAddr, int bindPort) throws IOException {
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        response.write(0x05); // version
        response.write(0x00); // success
        response.write(0x00); // reserved

        byte[] addrBytes = bindAddr.getAddress();
        if (addrBytes.length == 4) {
            response.write(0x01); // IPv4
        } else {
            response.write(0x04); // IPv6
        }

        response.write(addrBytes);
        response.write((bindPort >> 8) & 0xFF);
        response.write(bindPort & 0xFF);

        clientOut.write(response.toByteArray());
        clientOut.flush();
    }

    private void sendErrorResponse(byte errorCode) throws IOException {
        clientOut.write(new byte[]{0x05, errorCode, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        clientOut.flush();
    }

    private void startTunneling(Socket targetSocket, String targetHost, int targetPort) throws IOException {
        String tunnelInfo = String.format("%s -> %s:%d",  clientInfo, targetHost, targetPort);
        TransferSocket transfer =new TransferSocket(clientSocket,targetSocket);
        logger.debug("Starting tunnel: {}", tunnelInfo);


        // 使用虚拟线程处理双向数据流
        Thread clientToTarget = Thread.ofVirtual().start(() -> {
            try {
                transfer.localToRemote();
            } catch (IOException e) {
                logger.debug("Client to target tunnel closed: {}", tunnelInfo);
            } finally {
                closeQuietly(targetSocket);
            }
        });

        Thread targetToClient = Thread.ofVirtual().start(() -> {
            try {
                transfer.remoteToLocal();
            } catch (IOException e) {
                logger.debug("Target to client tunnel closed: {}", tunnelInfo);
            } finally {
                closeQuietly(clientSocket);
            }
        });

        try {
            clientToTarget.join();
            targetToClient.join();
            logger.info("Tunnel completed: {}", tunnelInfo);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Tunnel interrupted: {}", tunnelInfo);
            // Interrupt both worker threads
            clientToTarget.interrupt();
            targetToClient.interrupt();
        }
    }


    private void closeQuietly(Socket socket) {
        if (socket != null && !socket.isClosed()) {
            try {
                socket.close();
            } catch (IOException e) {
                logger.debug("Error closing socket: {}", e.getMessage());
            }
        }
    }
}