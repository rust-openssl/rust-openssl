# Overlay for vcpkg's built-in arm64-windows-static-md triplet, used by the
# windows-vcpkg-arm64 CI job.
#
# MSVC 14.51 (Visual Studio 2026, windows-11-arm image since
# actions/runner-images#14602) emits `bl __chkstk` before saving the link
# register in some ARM64 prologues. OpenSSL compiles with /Gs0, which puts a
# __chkstk call in every such prologue, so tls_parse_all_extensions returns
# into itself and every TLS handshake dies with STATUS_ACCESS_VIOLATION.
# Build OpenSSL with the 14.44 toolset the image still ships (the same
# workaround as ruby/ruby#19135). Remove this file once a fixed MSVC is on
# the image; if the image drops 14.44 first, vcpkg fails loudly here.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.44)
