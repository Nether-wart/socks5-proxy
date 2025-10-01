package com.example.socks5;

import com.example.socks5.config.Config;
import com.example.socks5.server.Socks5Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        try {
            logger.info("Starting SOCKS5 Proxy Server...");

            Config config = Config.load();

            Socks5Server server = new Socks5Server(config);

            // 添加关闭钩子
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down SOCKS5 proxy server...");
                server.shutdown();
            }));

            // 启动服务器
            server.start();

        } catch (Exception e) {
            logger.error("Failed to start SOCKS5 proxy server: {}", e.getMessage(), e);
            System.exit(1);
        }
    }
}