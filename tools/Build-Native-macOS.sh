#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
output_root=${repo_root}/KeepVaultMac/Native
reference_dir=${repo_root}/external/ML-DSA-reference

if [[ -L ${repo_root} || -L ${output_root:h} ]]; then
  print -u2 "Refusing to build through a symbolic-link workspace path."
  exit 1
fi

expected_commit='d35ba3fe5449bee3e6d43e1f296c3ca818bd36be'
actual_commit=$(<${reference_dir}/PINNED_COMMIT.txt)
actual_commit=${actual_commit//$'\r'/}
actual_commit=${actual_commit//$'\n'/}
if [[ ${actual_commit} != ${expected_commit} ]]; then
  print -u2 "The ML-DSA reference commit pin is not the reviewed source revision."
  exit 1
fi

while read -r expected relative_path; do
  [[ -z ${expected:-} ]] && continue
  source_file=${reference_dir}/${relative_path}
  if [[ ! -f ${source_file} || -L ${source_file} ]]; then
    print -u2 "Pinned ML-DSA source is missing or is a symbolic link: ${relative_path}"
    exit 1
  fi
  actual=$(shasum -a 256 -- "${source_file}" | awk '{print toupper($1)}')
  if [[ ${actual} != ${expected} ]]; then
    print -u2 "Pinned ML-DSA SHA-256 mismatch: ${relative_path}"
    exit 1
  fi
done < ${reference_dir}/SOURCE_SHA256SUMS

cc=$(xcrun --find clang)
cxx=$(xcrun --find clang++)
sdk_root=$(xcrun --sdk macosx --show-sdk-path)
link_flags=(
  -Wl,-dead_strip
  -Wl,-fatal_warnings
)

mldsa_sources=(
  sign.c
  packing.c
  polyvec.c
  poly.c
  ntt.c
  reduce.c
  rounding.c
  symmetric-shake.c
  fips202.c
)
mldsa_paths=()
for source_name in ${mldsa_sources[@]}; do
  mldsa_paths+=(${reference_dir}/ref/${source_name})
done

argon_root=${repo_root}/external/phc-winner-argon2
argon_sources=(
  ${argon_root}/src/argon2.c
  ${argon_root}/src/core.c
  ${argon_root}/src/encoding.c
  ${argon_root}/src/ref.c
  ${argon_root}/src/thread.c
  ${argon_root}/src/blake2/blake2b.c
)
argon_includes=(
  -I${argon_root}/include
  -I${argon_root}/src
  -I${argon_root}/src/blake2
)

build_architecture() {
  local architecture=$1
  local runtime=$2
  local output_dir=${output_root}/${runtime}
  local common_flags=(
    -arch
    ${architecture}
    -O2
    -DNDEBUG
    -fstack-protector-strong
    -fvisibility=hidden
    -fno-common
    -isysroot
    ${sdk_root}
    -mmacosx-version-min=14.0
    -Wall
    -Wextra
    -Wpedantic
  )

  mkdir -p -- ${output_dir}

  ${cxx} ${common_flags[@]} -DNOJIT -DBSD -fPIE -pthread \
    -o ${output_dir}/zpaq \
    ${repo_root}/external/zpaq/zpaq.cpp \
    ${repo_root}/external/zpaq/libzpaq.cpp \
    -Wl,-pie ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libkalyna_ref.dylib \
    -o ${output_dir}/libkalyna_ref.dylib \
    ${repo_root}/native/kalyna_ref_export.c \
    ${repo_root}/external/Kalyna-reference/kalyna.c \
    ${repo_root}/external/Kalyna-reference/tables.c \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    -install_name @rpath/libthreefish_ref.dylib \
    -o ${output_dir}/libthreefish_ref.dylib \
    ${repo_root}/native/threefish_ref_export.c \
    ${repo_root}/external/Skein-reference/NIST/CD/Reference_Implementation/skein.c \
    ${repo_root}/external/Skein-reference/NIST/CD/Reference_Implementation/skein_block.c \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -DDILITHIUM_MODE=5 \
    -I${reference_dir}/ref \
    -install_name @rpath/libmldsa87_ref.dylib \
    -o ${output_dir}/libmldsa87_ref.dylib \
    ${repo_root}/native/mldsa87_ref_export.c \
    ${mldsa_paths[@]} \
    -framework Security \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -dynamiclib -pthread \
    ${argon_includes[@]} \
    -install_name @rpath/libargon2_ref.dylib \
    -o ${output_dir}/libargon2_ref.dylib \
    ${repo_root}/native/argon2_ref_export.c \
    ${argon_sources[@]} \
    ${link_flags[@]}

  ${cc} ${common_flags[@]} -fPIE -pthread \
    ${argon_includes[@]} \
    -o ${output_dir}/argon2 \
    ${argon_root}/src/run.c \
    ${argon_sources[@]} \
    -Wl,-pie ${link_flags[@]}

  chmod 0755 ${output_dir}/zpaq ${output_dir}/argon2 ${output_dir}/*.dylib
  for artifact in ${output_dir}/zpaq ${output_dir}/argon2 ${output_dir}/*.dylib; do
    if [[ -L ${artifact} ]]; then
      print -u2 "Native build unexpectedly produced a symbolic link: ${artifact}"
      exit 1
    fi
    xcrun lipo ${artifact} -verify_arch ${architecture}
    file -- ${artifact}
  done
}

build_architecture arm64 osx-arm64
build_architecture x86_64 osx-x64

universal_dir=${output_root}/osx-universal
mkdir -p -- ${universal_dir}
artifacts=(zpaq argon2 libargon2_ref.dylib libkalyna_ref.dylib libmldsa87_ref.dylib libthreefish_ref.dylib)
for artifact_name in ${artifacts[@]}; do
  xcrun lipo -create \
    ${output_root}/osx-arm64/${artifact_name} \
    ${output_root}/osx-x64/${artifact_name} \
    -output ${universal_dir}/${artifact_name}
  chmod 0755 ${universal_dir}/${artifact_name}
  xcrun lipo ${universal_dir}/${artifact_name} -verify_arch arm64 x86_64
  file -- ${universal_dir}/${artifact_name}
done

print "macOS native builds complete: osx-arm64, osx-x64, and osx-universal"
