# Stage 1: Builder
# This stage compiles the AiDA IDA Pro plugin.
FROM ubuntu:22.04 AS builder

LABEL description="Build container for the AiDA IDA Pro plugin"

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential cmake git && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the IDA SDK from the build context.
# The user must place their IDA SDK into a directory named 'idasdk'
# in the same directory as this Dockerfile before building.
COPY idasdk /idasdk
ENV IDASDK /idasdk

# Copy the project source code into the container
COPY . .

# Initialize git submodules (required for ida-cmake).
# This is run after copying the source, which includes the .gitmodules file.
RUN git config --global --add safe.directory /app
RUN git submodule update --init --recursive

# Configure the CMake project
RUN cmake -B build

# Build the project in Release configuration
RUN cmake --build build --config Release

# Create a directory to store the final plugin and move the compiled artifact there.
# This provides a known location to copy from in the next stage.
RUN mkdir /plugin && find /app/build -type f -name 'aida*.*' -exec mv {} /plugin/ \;

# ---

# Stage 2: Final Image
# This stage contains only the compiled plugin for easy extraction.
FROM scratch

# Copy the compiled plugin from the known location in the builder stage.
# The final image will contain only the plugin artifact.
COPY --from=builder /plugin/* /
