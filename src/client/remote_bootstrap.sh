# Server-side bootstrap, piped over SSH into `sh -s -- <version> <args...>`.
# Always runs ~/.thther/bin/thther-<version> (never a `thther` on PATH), so the
# server matches the client exactly; installs it from the release if missing.
# Diagnostics go to stderr: stdout carries only the agent's JSON line.
set -e

ver=$1
shift

die() {
    echo "thther: $*" >&2
    exit 127
}

dir="$HOME/.thther/bin"
cached="$dir/thther-$ver"
if [ -x "$cached" ]; then
    exec "$cached" "$@"
fi

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
    *) die "no prebuilt binary for $(uname -s)-$(uname -m); place the binary at $cached manually" ;;
esac

name="thther-v$ver-$target"
url="https://github.com/lakakala/thther-tty/releases/download/v$ver/$name.tar.gz"

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        return 1
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "thther: installing $name into $dir" >&2
fetch "$url" "$tmp/$name.tar.gz" || die "download failed: $url (needs curl or wget and access to github.com)"
fetch "$url.sha256" "$tmp/$name.tar.gz.sha256" || die "download failed: $url.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$name.tar.gz.sha256" >/dev/null) || die "checksum mismatch for $name.tar.gz"
elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp" && shasum -a 256 -c "$name.tar.gz.sha256" >/dev/null) || die "checksum mismatch for $name.tar.gz"
else
    die "neither sha256sum nor shasum found; cannot verify download"
fi

tar xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$dir"
chmod +x "$tmp/$name/thther"
mv "$tmp/$name/thther" "$cached.tmp.$$"
mv -f "$cached.tmp.$$" "$cached"

rm -rf "$tmp"
trap - EXIT
exec "$cached" "$@"
