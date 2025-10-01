package com.example.socks5.server;

import com.example.socks5.auth.Authenticator;
import com.example.socks5.config.Config;
import com.example.socks5.server.handler.Socks5Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Socks5Server {
    private static final Logger logger = LoggerFactory.getLogger(Socks5Server.class);
    
    private final Config config;
    private final Authenticator authenticator;
    private volatile boolean running;
    private ServerSocket serverSocket;
    
    public Socks5Server(Config config) {
        this.config = config;
        this.authenticator = new Authenticator(config);
    }
    
    public void start() {
        running = true;
        int port = config.getServer().getPort();
        String bindAddress = config.getServer().getBind();
        
        try {
            serverSocket = new ServerSocket(port, 50, java.net.InetAddress.getByName(bindAddress));
            
            logger.info("SOCKS5 Proxy Server started on {}:{}", bindAddress, port);
            logger.info("Using virtual threads for improved scalability");
            logger.info("Username/password authentication is REQUIRED");
            
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    
                    // 为每个客户端连接创建虚拟线程
                    Thread virtualThread = Thread.ofVirtual().start(() -> {
                        Socks5Handler handler = new Socks5Handler(clientSocket, authenticator);
                        handler.run();
                    });
                    
                    logger.debug("Started virtual thread: {} for client: {}", 
                                virtualThread.getName(), clientSocket.getInetAddress().getHostAddress());
                    
                } catch (IOException e) {
                    if (running) {
                        logger.error("Error accepting client connection: {}", e.getMessage());
                    } else {
                        logger.debug("Server socket closed while accepting connections");
                    }
                }
            }
            
        } catch (IOException e) {
            logger.error("Failed to start SOCKS5 server: {}", e.getMessage(), e);
        } finally {
            shutdown();
        }
    }
    
    public void shutdown() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                logger.debug("Error closing server socket: {}", e.getMessage());
            }
        }
        logger.info("SOCKS5 Proxy Server stopped");
    }
}