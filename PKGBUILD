# Maintainer: Axon Maintainers <team@axon.org>
pkgname=axon
pkgver=1.0.0
pkgrel=1
pkgdesc="Streaming security evidence normalization and export CLI"
arch=('x86_64' 'aarch64')
url="https://github.com/axon/axon"
license=('Apache')
depends=('glibc')
makedepends=('go' 'gzip')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('REPLACE_WITH_SHA256')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  export CGO_ENABLED=0
  make build
  gzip -n -9 -c man/axon.1 > axon.1.gz
}

check() {
  cd "$srcdir/$pkgname-$pkgver"
  export GOCACHE="$srcdir/.gocache"
  go test ./...
}

package() {
  cd "$srcdir/$pkgname-$pkgver"

  install -Dm755 "bin/$pkgname" "$pkgdir/usr/bin/$pkgname"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 axon.1.gz "$pkgdir/usr/share/man/man1/axon.1.gz"

  install -Dm644 "bin/$pkgname.bash" "$pkgdir/usr/share/bash-completion/completions/$pkgname"
  install -Dm644 "bin/_$pkgname" "$pkgdir/usr/share/zsh/site-functions/_$pkgname"
  install -Dm644 "bin/$pkgname.fish" "$pkgdir/usr/share/fish/vendor_completions.d/$pkgname.fish"
}
