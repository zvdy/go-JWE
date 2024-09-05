# Use the official Golang image with version 1.23 to create a build artifact.
# This is the first stage of a multi-stage build.
FROM golang:1.23 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the src directory to the Working Directory inside the container
COPY src/main ./main
COPY src/claims ./claims

# Build the Go app
RUN go build -o /app/main ./main/main.go

# Use the same Golang image for the final stage to ensure compatibility
FROM golang:1.23

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Ensure the binary has execute permissions
RUN chmod +x ./main

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
ENTRYPOINT ["./main"]