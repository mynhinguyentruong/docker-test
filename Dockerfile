# Dockerfile is used to build Docker Image

# PULL latest ollama/ollama image
FROM ollama/ollama:latest

# SET environment variable PORT="11434"
ENV PORT "11434"

EXPOSE 8080 

