#!/bin/sh
curl -sSL https://dot.net/v1/dotnet-install.sh > dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh -c 9.0
dotnet --version
cd ShalzuthBlog
dotnet run
find ShalzuthBlog/bin/static