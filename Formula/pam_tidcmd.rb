# Homebrew formula for pam_tidcmd. To publish it, copy it into the Formula
# directory of a tap (a repository named homebrew-<name>) and set url and
# sha256 to those of a release tarball.
#
# Homebrew only puts the files in place. `sudo pam_tidcmd install` then copies
# the module to /Library/Security/pam_tidcmd, because PAM must never load a
# module from Homebrew's prefix: it is writable by the user, and upgrades,
# cleanup and uninstalling delete files from it, which would stop sudo from
# starting.
class PamTidcmd < Formula
  desc "Touch ID for sudo that shows the command in the dialog"
  homepage "https://github.com/OWNER/pam_tidcmd"
  url "https://github.com/OWNER/pam_tidcmd/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  head "https://github.com/OWNER/pam_tidcmd.git", branch: "main"

  depends_on :macos

  on_macos do
    depends_on macos: :sonoma # /etc/pam.d/sudo_local
  end

  def install
    # The module and the probe are built for arm64e, arm64 and x86_64: sudo is
    # arm64e on Apple silicon.
    ENV.permit_arch_flags
    system "make", "pam_tidcmd.so", "pam_tidcmd_probe"
    (libexec/"pam_tidcmd").install "pam_tidcmd.so", "pam_tidcmd_probe"
    (libexec/"pam_tidcmd").install "pam_tidcmd.sh" => "pam_tidcmd"
    bin.install_symlink libexec/"pam_tidcmd/pam_tidcmd"
  end

  def caveats
    <<~EOS
      sudo is unchanged so far. To use the module for sudo, run:
        sudo #{opt_bin}/pam_tidcmd install
      It asks you to approve a Touch ID dialog, and keeps the module only if that works.

      Run the same command after `brew upgrade pam_tidcmd` to update the module sudo uses.
      Before `brew uninstall pam_tidcmd`, run:
        sudo #{opt_bin}/pam_tidcmd uninstall

      If sudo ever stops starting ("unable to initialize PAM"), run this, without sudo:
        /Library/Security/pam_tidcmd/pam_tidcmd rescue
    EOS
  end

  test do
    system libexec/"pam_tidcmd/pam_tidcmd_probe", "module", libexec/"pam_tidcmd/pam_tidcmd.so"
    assert_match "usage:", shell_output("#{bin}/pam_tidcmd 2>&1", 2)
  end
end
