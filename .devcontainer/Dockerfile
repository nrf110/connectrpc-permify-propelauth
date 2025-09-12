FROM nrf110/go-dind:latest

RUN go install github.com/bufbuild/buf/cmd/buf@v1.55.1
RUN go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install github.com/bufbuild/connect-go/cmd/protoc-gen-connect-go@latest
