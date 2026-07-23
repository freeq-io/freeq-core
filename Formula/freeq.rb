class Freeq < Formula
  desc "Post-quantum encrypted overlay network"
  homepage "https://getfreeq.io"
  url "https://github.com/freeq-io/freeq-core.git", branch: "main"
  version "0.1.0-alpha"
  license "AGPL-3.0-only"
  head "https://github.com/freeq-io/freeq-core.git", branch: "main"

  depends_on "rust" => :build

  def install
    libexec.install "Cargo.toml", "Cargo.lock", "cli", "crates", "daemon", "docs", "scripts", "tools"

    cd libexec do
      ENV["FREEQ_PACKAGE_ROOT"] = libexec
      system "cargo", "install", "--path", "cli", "--root", prefix
      system "cargo", "install", "--path", "daemon", "--root", prefix
    end
  end

  def caveats
    <<~EOS
      Prepare this Mac and start the local setup node:
        freeq setup

      Connect to a gateway/peer file placed in ~/FreeQ:
        freeq gateway

      Stop FreeQ and roll networking back to normal:
        freeq stop

      Update FreeQ:
        brew upgrade freeq
    EOS
  end

  test do
    assert_match "freeq", shell_output("#{bin}/freeq --help")
  end
end
