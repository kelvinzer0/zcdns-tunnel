# ZCDNS Tunnel

**Stateless SSH Port Forwarding & Shared HTTP Proxy via DNS**

This project provides a stateless, dynamic SSH port forwarding solution that allows you to expose local services to the internet using custom domains. Authentication and authorization are handled entirely through DNS records, eliminating the need for a server-side database. Additionally, it now supports sharing port 80 across multiple domains using a built-in HTTP reverse proxy.

## How It Works

1.  **DNS Setup:**
    *   Create a CNAME record for your custom domain (e.g., `your-domain.com`) that points to the tunnel server's domain (e.g., `server.tunnellku.net`).
    *   Add a TXT record to your domain with your SSH public key:

        ```
        zcdns-ssh-key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
        ```

2.  **Client-Side:** Initiate an SSH connection to the server, using your domain as the username. The `-L` flag forwards a local port to the desired destination on the server, or the `-R` flag forwards a remote port on the server to a local destination.

    *   **Local Forwarding (`-L`):** Expose a local service to the internet via the server's IP.
        ```bash
        ssh your-domain.com@your-server.com -p 2222 -L 80:localhost:80
        ```
        (Traffic from internet to `your-server.com:80` goes to `localhost:80` on your local machine)

    *   **Remote Forwarding (`-R`):** Open a port on the server that forwards to your local service. To make it accessible from the internet, bind to `0.0.0.0`.
        ```bash
        ssh your-domain.com@your-server.com -p 2222 -R 0.0.0.0:8080:localhost:80
        ```
        (Traffic from `your-server.com:8080` goes to `localhost:80` on your local machine)

    *   **HTTP Reverse Proxy (Shared Port 80):** To have the server act as a reverse proxy for your domain on the shared port 80, pass the `HTTP=TRUE` environment variable. The server will listen on a dynamic port and the central proxy on port 80 will forward requests for your domain to your local service.
        ```bash
        HTTP=TRUE ssh -N -f your-domain.com@your-server.com -p 2222 -R 0.0.0.0:0:localhost:8083
        ```
        (Traffic from the internet to `http://your-domain.com` will be proxied by the server to `localhost:8083` on your local machine via the SSH tunnel. The server allocates a random port for the tunnel endpoint, but the central proxy handles the public-facing routing on port 80.)

3.  **Server-Side:** The Go application listens for SSH connections and HTTP requests on port 80. When a connection is received, it:
    *   Parses the username (for SSH) or `Host` header (for HTTP) to get the domain.
    *   **Authorizes** the request by verifying that the domain's CNAME record points to the configured validation domain.
    *   **Authenticates** the user by looking up the `zcdns-ssh-key` TXT record and comparing it with the public key provided by the client.
    *   If all checks pass, the server establishes the tunnel or proxies the HTTP request.

## Features

*   **Stateless and "DB-less":** No database or server-side state to manage. All configuration is in DNS.
*   **DNS-Based Authentication & Authorization:** Securely manage access and routing through your DNS provider.
*   **Supports both Local (`-L`) and Remote (`-R`) Port Forwarding:** Flexible options for exposing services.
*   **Shared Port 80 HTTP Proxy:** Automatically routes HTTP traffic on port 80 to the correct client based on the `Host` header.
*   **Simple Client-Side Setup:** Uses the standard `ssh` command.
*   **Scalable and Resilient:** The stateless nature of the server makes it easy to scale and deploy.

## Use Cases

*   **Exposing local development servers.**
*   **Custom domains for SaaS applications.**
*   **Running services on dynamic IP addresses.**
*   **Building decentralized and resilient systems.**
