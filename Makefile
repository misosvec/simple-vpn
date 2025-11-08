# Makefile for running Go VPN client and server containers

IMAGE_CLIENT = vpn-client
IMAGE_SERVER = vpn-server
NETWORK = vpn-network
WORKDIR = /app

.PHONY: client server build-client build-server ensure-network

# Default targets to run the containers
client: ensure-network build-client
	@echo "Starting VPN client container..."
	docker run --cap-add=NET_ADMIN --device /dev/net/tun -it --rm \
		-v "$(PWD):$(WORKDIR)" \
		--network $(NETWORK) \
		-w $(WORKDIR) \
		$(IMAGE_CLIENT) sh

server: ensure-network build-server
	@echo "Starting VPN server container..."
	docker run --cap-add=NET_ADMIN --device /dev/net/tun -it --rm \
		--name vpn-server-cont \
		--network $(NETWORK) \
		-v "$(PWD):$(WORKDIR)" \
		-w $(WORKDIR) \
		$(IMAGE_SERVER) sh

# --- Helper targets ---

build-client:
	@if [ -z "$$(docker images -q $(IMAGE_CLIENT))" ]; then \
		echo "Building $(IMAGE_CLIENT) image..."; \
		docker build -t $(IMAGE_CLIENT) -f client/Dockerfile .; \
	else \
		echo "$(IMAGE_CLIENT) image already exists."; \
	fi

build-server:
	@if [ -z "$$(docker images -q $(IMAGE_SERVER))" ]; then \
		echo "Building $(IMAGE_SERVER) image..."; \
		docker build -t $(IMAGE_SERVER) -f server/Dockerfile .; \
	else \
		echo "$(IMAGE_SERVER) image already exists."; \
	fi

ensure-network:
	@if ! docker network inspect $(NETWORK) >/dev/null 2>&1; then \
		echo "Creating network $(NETWORK)..."; \
		docker network create $(NETWORK); \
	else \
		echo "Network $(NETWORK) already exists."; \
	fi

clean-client:
	@echo "Forcefully removing any running VPN client containers..."
	@docker ps -aq --filter ancestor=$(IMAGE_CLIENT) | xargs -r docker rm -f
	@docker ps -aq --filter name=vpn-client-cont | xargs -r docker rm -f
	@echo "Done."

clean-server:
	@echo "Forcefully removing any running VPN server containers..."
	@docker ps -aq --filter ancestor=$(IMAGE_SERVER) | xargs -r docker rm -f
	@docker ps -aq --filter name=vpn-server-cont | xargs -r docker rm -f
	@echo "Done."

clean-all: clean-client clean-server
	@echo "All containers and images removed."
