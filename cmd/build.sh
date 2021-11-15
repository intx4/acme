#!/bin/bash

rm acme
cd ./terminator && go build  && cd ..
cd ./dns && go build && cd ..
cd ./tlsServer && go build && cd ..
cd ./httpChall && go build && cd ..
cd ./types && go build && cd ..
cd ./funcs && go build && cd .. 
go mod tidy
go build


