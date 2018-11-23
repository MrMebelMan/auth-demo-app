FROM golang:alpine AS build
ADD . /go/src/github.com/jakm/auth-demo-app
RUN go install github.com/jakm/auth-demo-app

FROM alpine
COPY --from=build /go/bin/auth-demo-app /opt/auth-demo-app/auth-demo-app
ADD cert /opt/auth-demo-app/cert
ADD templates /opt/auth-demo-app/templates
WORKDIR /opt/auth-demo-app
CMD /opt/auth-demo-app/auth-demo-app
