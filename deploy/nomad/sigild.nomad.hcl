# Nomad jobspec for sigild. SKELETON — NOT APPLIED.
# The single-VM systemd shape (deploy/systemd/) is the starting point; this is
# the next step up (orchestrated VMs) before Kubernetes is ever considered.

job "sigild" {
  datacenters = ["dc1"]
  type        = "service"

  group "server" {
    count = 1

    network {
      port "http" {
        to = 8080
      }
    }

    task "sigild" {
      driver = "docker"

      config {
        image = "ghcr.io/PLACEHOLDER/sigild:latest" # set once an image is published
        ports = ["http"]
      }

      # Secrets injected via Nomad template/Vault, never baked into the image.
      env {
        SIGILD_ADDR = ":8080"
      }

      resources {
        cpu    = 250
        memory = 128
      }

      service {
        name = "sigild"
        port = "http"

        check {
          type     = "http"
          path     = "/healthz"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
