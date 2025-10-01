package com.example.socks5.auth;

import com.example.socks5.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(Authenticator.class);

    private final Map<String, String> users;

    public Authenticator(Config config) {
        this.users = new HashMap<>();
        loadUsers(config);
    }

    private void loadUsers(Config config) {
        try {
            List<Config.UserConfig> userConfigs = config.getUsers();
            if (userConfigs != null) {
                for (Config.UserConfig user : userConfigs) {
                    if (user.getName() != null && user.getPwd() != null) {
                        users.put(user.getName(), user.getPwd());
                    }
                }
            }
            logger.info("Loaded {} users from config", users.size());

            if (logger.isDebugEnabled()) {
                users.keySet().forEach(username ->
                    logger.debug("Registered user: {}", username));
            }
        } catch (Exception e) {
            logger.error("Failed to load users from config", e);
        }
    }

    public boolean authenticate(String username, String password) {
        if (username == null || password == null) {
            logger.warn("Authentication attempt with null username or password");
            return false;
        }

        try {
            String storedPassword = users.get(username);
            boolean authenticated = storedPassword != null && storedPassword.equals(password);

            if (authenticated) {
                logger.info("User authenticated successfully: {}", username);
            } else {
                logger.warn("Authentication failed for user: {}", username);
            }

            return authenticated;
        } catch (Exception e) {
            logger.error("Error during authentication for user: {}", username, e);
            return false;
        }
    }
}