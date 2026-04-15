# Use the official GCC image from the Docker Hub
FROM gcc:latest

# Install OpenSSL library
RUN apt-get update && apt-get install -y libssl-dev

# Set the working directory inside the container
WORKDIR /app

# Copy the C program to the working directory
COPY login.c /app/
COPY start.sh /app/
COPY users.txt /app/
COPY hash_utils.c /app/
COPY hash_utils.h /app/
COPY generate_hashed_users.c /app/

# Compile the C program
RUN gcc /app/hash_utils.c /app/generate_hashed_users.c -o /app/generate_hashed_users -lssl -lcrypto
RUN gcc /app/hash_utils.c /app/login.c -o /app/login -lssl -lcrypto

# Make start.sh executable
RUN chmod +x /app/start.sh

# Specify the command to run the program
CMD ["/bin/bash", "/app/start.sh"]
