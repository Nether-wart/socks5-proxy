package com.example.socks5.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Config {
    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    private ServerConfig server;
    private List<UserConfig> users;

    // Jackson 需要默认构造函数
    public Config() {}

    public static class ServerConfig {
        private int port;
        private String bind;

        public ServerConfig() {}

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }

        public String getBind() { return bind; }
        public void setBind(String bind) { this.bind = bind; }
    }

    public static class UserConfig {
        private String name;
        private String pwd;

        public UserConfig() {}

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getPwd() { return pwd; }
        public void setPwd(String pwd) { this.pwd = pwd; }
    }

    public ServerConfig getServer() { return server; }
    public void setServer(ServerConfig server) { this.server = server; }

    public List<UserConfig> getUsers() { return users; }
    public void setUsers(List<UserConfig> users) { this.users = users; }

    public static Config load() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Path configPath = Paths.get("config.json");

        try {
            String jsonContent = Files.readString(configPath);
            Config config = mapper.readValue(jsonContent, Config.class);
            logger.info("Loaded config from: {}", configPath.toAbsolutePath());
            return config;
        } catch (Exception e) {
            logger.error("Failed to load config file", e);
            throw new RuntimeException(e);
        }
    }
}