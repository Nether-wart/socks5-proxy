package com.example.socks5.server.handler;

import java.io.IOException;
import java.net.Socket;

public class TransferSocket {
    Socket local;
    Socket remote;

    public TransferSocket(Socket local, Socket remote) {
        this.local = local;
        this.remote = remote;
    }

    public void localToRemote()throws IOException {
        local.getInputStream().transferTo(remote.getOutputStream());
    }

    public void remoteToLocal()throws IOException {
        remote.getInputStream().transferTo(local.getOutputStream());
    }
}
