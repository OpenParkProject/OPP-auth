#!/bin/sh
set -e

echo "Getting API specs..."
rm -rf /tmp/OPP-common
git clone -b main --depth 1 https://github.com/OpenParkProject/OPP-common.git /tmp/OPP-common
echo "Adding localhost to servers"
sed -i 's/servers:/servers:\n  - url: http:\/\/localhost:8080\/api\/v1\n    description: Local server/' /tmp/OPP-common/openapi.yaml

echo "Generating API..."
cd src
mkdir -p api
cp -a /tmp/OPP-common/openapi.yaml api/openapi.yaml
go generate && echo "API generated" || echo "API generation failed"

echo "Building app..."
go build -buildvcs=false -o /go/bin/opp-auth .

mkdir -p /root/keys && \
openssl genrsa -out /root/keys/private.pem 4096 && \
openssl rsa -in /root/keys/private.pem -pubout -out /root/keys/public.pem
export PRIVATE_KEY=$(cat /root/keys/private.pem | base64 -w 0)
export PUBLIC_KEY=$(cat /root/keys/public.pem | base64 -w 0)

echo "Starting app..."
/go/bin/opp-auth
