# syntax=docker/dockerfile:1
ARG GO_VERSION=1.21
ARG SVC_NAME=iw_svc_identity

FROM golang:${GO_VERSION}-alpine AS build-stage

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

#copy the file to build
COPY main.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /${SVC_NAME}

FROM build-stage AS run-test-stage
RUN go test -v ./...

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian12 AS build-release-stage

WORKDIR /

COPY --from=build-stage /${SVC_NAME} /${SVC_NAME}

USER nonroot:nonroot

# Run
CMD ["/${SVC_NAME}"]