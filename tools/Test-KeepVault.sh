#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
test_project=${repo_root}/KeepVaultMac.Tests/KeepVaultMac.Tests.csproj
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
if [[ ! -x ${dotnet_command} ]]; then
  dotnet_command=dotnet
fi

no_build=0
for arg in "$@"; do
  if [[ ${arg} == "--no-build" ]]; then
    no_build=1
    break
  fi
done

if (( no_build == 0 )); then
  ${dotnet_command} build ${test_project} -c Release --nologo
fi

# Pass all arguments through to runner
exec ${dotnet_command} run --project ${test_project} -c Release --no-build --no-restore -- "$@"
