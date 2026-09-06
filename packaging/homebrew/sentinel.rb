# Homebrew formula for sentinel CLI (WP-16).
# Maintained by hand as a reproducible reference; goreleaser brews block
# regenerates this on each tag release into homebrew-sentinel tap.
class Sentinel < Formula
  desc "Sentinel secret-hygiene CLI"
  homepage "https://github.com/Ferrum-Sidereum/sentinel"
  version "0.0.0"
  license "TBD"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Ferrum-Sidereum/sentinel/releases/download/v0.0.0/sentinel_0.0.0_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/Ferrum-Sidereum/sentinel/releases/download/v0.0.0/sentinel_0.0.0_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Ferrum-Sidereum/sentinel/releases/download/v0.0.0/sentinel_0.0.0_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/Ferrum-Sidereum/sentinel/releases/download/v0.0.0/sentinel_0.0.0_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install "sentinel"
  end

  test do
    assert_match "sentinel", shell_output("#{bin}/sentinel version")
  end
end
