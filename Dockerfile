## Stage 1: Build the application
#FROM golang:1.22 as builder
#
## Set the Current Working Directory inside the container
#WORKDIR /app
#
## Copy go mod and sum files
#COPY go.mod go.sum ./
#
## Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
#RUN go mod download
#
## Copy the source code
#COPY . .

# Build the Go app
#RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -extldflags='-static'" -a -installsuffix cgo -o trivy-admission-controller main.go

# Stage 2: Install Trivy
FROM aquasec/trivy:latest AS trivy

# Stage 3: Create the final image
#FROM cgr.dev/chainguard/static:latest
FROM golang:1.22

# Copy the Trivy binary from the trivy stage
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Copy the binary from the builder stage
#COPY --from=builder /app/trivy-admission-controller /trivy-admission-controller
COPY trivy-admission-controller /trivy-admission-controller

# Expose port 8443 to the outside world
EXPOSE 8443

# Command to run the executable
CMD ["/trivy-admission-controller"]
